/* Copyright (C) 2004 MySQL AB
   Copyright (C) 2004-2018 Alexey Kopytov <akopytov@gmail.com>
   Copyright (C) 2004-2018 MICROSOFT <ryanston@microsoft.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
*/

#ifdef STDC_HEADERS
# include <stdio.h>
#endif
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_STRING_H
# include <string.h>
#endif
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif
#include <stdio.h>

// ODBC stuff
//
#include <sql.h>
#include <sqlext.h>
#define _SQLNCLI_ODBC_

#include <assert.h>

#include "sb_options.h"
#include "db_driver.h"
#include "sb_rand.h"

#define DEBUG(format, ...)                      \
  do {                                          \
	if (SB_UNLIKELY(global_arguments.is_debug != 0))           \
	  log_text(LOG_DEBUG, format, __VA_ARGS__); \
  } while (0)

static inline const char* SAFESTR(const char* s)
{
	return s ? s : "(null)";
}

#define x_DefaultNetworkProtocol	TCPIP
#define x_DefaultNetworkPacketSize	4096
#define x_ConnectionStringFormat	"driver={ODBC Driver 17 for SQL Server};server=%s;database=%s;%s;app=sysbench;trusted_connection=yes"
#define x_NamedPipesNetwork			"dbnmpntw"
#define x_TcpIpNetwork				"dbmssocn"
#define x_TcpServerNameFormat		"tcp:%s,%d"
#define x_TcpServerNameFormatNI		"tcp:%s"
#define x_NpServerNameFormat		"np:\\\\.\\pipe\\sql\\query"
#define x_NpServerNameFormatNI		"np:\\\\.\\pipe\\MSSQL$%s\\sql\\query"
#define x_ServerNameFormatRaw		"%s"
#define x_DefaultLoginTimeout		5
#define x_MaxDatabaseConnectRetries	10

/* Maximum length of text representation of bind parameters */
#define MAX_PARAM_LENGTH 3000UL

/* MSSQL driver arguments */

static sb_arg_t mssql_drv_args[] =
{
	SB_OPT("mssql-host", "MSSQL server host", "localhost", LIST),
	SB_OPT("mssql-port", "MSSQL server port", "1433", LIST),
	SB_OPT("mssql-trusted-auth", "Use trusted authentication", "on", BOOL),
	SB_OPT("mssql-db", "MSSQL  database name", "sbtest", STRING),
	SB_OPT("mssql-debug", "Trace all client library calls", "off", BOOL),
	SB_OPT("mssql-ignore-errors", "list of errors to ignore, or \"all\"", "1213,1020,1205", LIST),
	SB_OPT("mssql-dry-run", "Dry run, pretend all API calls are successful without executing them", "off", BOOL),
	SB_OPT_END
};

typedef enum
{
	tcp,
	named_pipes
} mssql_protocol_t;

typedef struct
{
	sb_list_t* hosts_list;
	sb_list_t* ports;
	const char* database_name;
	unsigned char use_trusted_authentication;
	unsigned char is_debug;
	sb_list_t* ignored_errors_list;
	unsigned int is_dry_run;
	unsigned int network_packet_size;
	unsigned int login_timeout;
} mssql_drv_args_t;

typedef struct
{
	SQLHDBC connection_hdl;
	const char* host_name;
	const char* database_name;
	unsigned int port;
	bool is_named_instance;
	const char* instance_name;
} mssql_connection_t;

static mssql_connection_t* mssql_connection_alloc()
{
	mssql_connection_t* pconnection = malloc(sizeof(mssql_connection_t));

	pconnection->connection_hdl = SQL_NULL_HANDLE;
	pconnection->host_name = NULL;
	pconnection->database_name = NULL;
	pconnection->port = 0;
	pconnection->is_named_instance = false;
	pconnection->instance_name = NULL;

	return pconnection;
}

typedef struct
{
	SQLSMALLINT input_output_type;
	SQLSMALLINT value_type;
	SQLSMALLINT parameter_type;
	int column_length;
} mssql_parameter_t;

typedef struct
{
	SQLHSTMT statement_hdl;
	char* statement_name;
	int is_prepared;
	int count_of_parameters;
	mssql_parameter_t* parameter_types;
	char** parameter_values;
} mssql_statement_t;

typedef struct
{
	db_bind_type_t db_type;
	SQLSMALLINT value_type;
	SQLSMALLINT parameter_type;
	int size;
} db_mssql_bind_map_t;

/* DB-to-MSSQL bind types map */
db_mssql_bind_map_t db_mssql_bind_map[] =
{
	{DB_TYPE_TINYINT, SQL_C_TINYINT, SQL_TINYINT, 1},
	{DB_TYPE_SMALLINT, SQL_C_SHORT, SQL_SMALLINT, 2},
	{DB_TYPE_INT, SQL_C_LONG, SQL_INTEGER, 4},
	{DB_TYPE_BIGINT, SQL_C_SBIGINT, SQL_BIGINT, 8},
	{DB_TYPE_FLOAT, SQL_C_FLOAT, SQL_REAL, 0},
	{DB_TYPE_DOUBLE, SQL_C_DOUBLE, SQL_DOUBLE, 0},
	{DB_TYPE_DATETIME, SQL_C_TYPE_TIMESTAMP, SQL_DATETIME, 0},
	{DB_TYPE_TIMESTAMP, SQL_C_TYPE_TIMESTAMP, SQL_TIMESTAMP, 0},
	{DB_TYPE_CHAR, SQL_C_CHAR, SQL_CHAR, MAX_PARAM_LENGTH},
	{DB_TYPE_VARCHAR, SQL_C_WCHAR, SQL_WCHAR, MAX_PARAM_LENGTH},
	{DB_TYPE_NONE, 0}
};

/* driver args */
static mssql_drv_args_t global_arguments;

/* whether server-side prepared statemens should be used */
static char global_use_prepared_statements;

/* Positions in the list of hosts/ports/sockets. Protected by pos_mutex */
static sb_list_item_t* hosts_pos;
static sb_list_item_t* ports_pos;
static sb_list_item_t* sockets_pos;
static pthread_mutex_t pos_mutex;

/* ODBC environment handle */
HENV global_environment_hdl;

/* MSSQL driver operations */
static int mssql_driver_init(void);
static int mssql_driver_on_thread_init(int);
static int mssql_driver_describe(drv_caps_t*);
static int mssql_driver_connect(db_conn_t*);
static int mssql_driver_disconnect(db_conn_t*);
static int mssql_driver_prepare(db_stmt_t*, const char*, size_t);
static int mssql_driver_parameter_bind(db_stmt_t*, db_bind_t*, size_t);
static int mssql_driver_bind_result(db_stmt_t*, db_bind_t*, size_t);
static db_error_t mssql_driver_execute(db_stmt_t*, db_result_t*);
static int mssql_driver_fetch(db_result_t*);
static int mssql_driver_fetch_row(db_result_t*, db_row_t*);
static db_error_t mssql_driver_query_exec(db_conn_t*, const char*, size_t, db_result_t*);
static int mssql_driver_results_free(db_result_t*);
static int mssql_driver_close(db_stmt_t*);
static int mssql_driver_finished(void);

/* MSSQL driver definition */
static db_driver_t mssql_driver =
{
	.sname = "mssql",
	.lname = "Microsoft SQL Server driver",
	.args = mssql_drv_args,
	.ops = {
		.init = mssql_driver_init,
		.thread_init = mssql_driver_on_thread_init,
		.describe = mssql_driver_describe,
		.connect = mssql_driver_connect,
		.disconnect = mssql_driver_disconnect,
		.prepare = mssql_driver_prepare,
		.bind_param = mssql_driver_parameter_bind,
		.bind_result = mssql_driver_bind_result,
		.execute = mssql_driver_execute,
		.fetch = mssql_driver_fetch,
		.fetch_row = mssql_driver_fetch_row,
		.free_results = mssql_driver_results_free,
		.close = mssql_driver_close,
		.query = mssql_driver_query_exec,
		.done = mssql_driver_finished
	}
};
/* ODBC error handler */
static int get_odbc_error_info(SQLSMALLINT handleType, SQLHANDLE handle, char* location)
{
	SQLCHAR state[6];
	SQLCHAR message[SQL_MAX_MESSAGE_LENGTH];
	SQLSMALLINT error = 0;
	SDWORD nativeError;
	SQLSMALLINT messageLength;
	SQLRETURN getDiagRecReturn;

	while (true)
	{
		getDiagRecReturn = SQLGetDiagRec(
			handleType,
			handle,
			++error,
			(SQLCHAR*)&state,
			&nativeError,
			(SQLCHAR*)&message,
			ARRAYSIZE(message),
			&messageLength);

		if (getDiagRecReturn == SQL_NO_DATA)
		{
			break;
		}

		if (getDiagRecReturn == SQL_SUCCESS || getDiagRecReturn == SQL_SUCCESS_WITH_INFO)
		{
			// Output error information to the client.
			//
			log_text(LOG_FATAL,
					 "Database operation (%s) failed:  %s (%d), state %s",
					 location,
					 message,
					 nativeError,
					 state);

			return nativeError;
		}
	}

	return 1;
}

static db_error_t get_odbc_error(db_conn_t* pconn, db_stmt_t* sb_stmt, const char* location, const char* query,
								 sb_counter_type_t* counter)
{
	sb_list_item_t* pos;
	unsigned int tmp;
	SQLCHAR state[6];
	SQLCHAR message[SQL_MAX_MESSAGE_LENGTH];
	SQLSMALLINT error = 0;
	SDWORD nativeError;
	SQLSMALLINT messageLength;

	mssql_statement_t* db_mssql_stmt = (mssql_statement_t*)sb_stmt->ptr;
	HSTMT* hstmt = db_mssql_stmt->statement_hdl;

	SQLRETURN ret = SQLGetDiagRec(SQL_HANDLE_STMT,
								  db_mssql_stmt->statement_hdl,
								  ++error,
								  (SQLCHAR*)&state,
								  &nativeError,
								  (SQLCHAR*)&message,
								  ARRAYSIZE(message),
								  &messageLength);

	if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO)
	{
		// Output error information to the client.
		//
		log_text(LOG_FATAL,
				 "Database operation (%s) failed:  %s (%d), state %s",
				 location,
				 message,
				 nativeError,
				 state);


		DEBUG("mysql_errno(%p) = %u", hstmt, pconn->sql_errno);
		DEBUG("mysql_state(%p) = %s", hstmt, SAFESTR(pconn->sql_state));
		DEBUG("mysql_error(%p) = %s", hstmt, SAFESTR(pconn->sql_errmsg));

		pconn->sql_errno = (int)error;
		pconn->sql_state = state;
		pconn->sql_errmsg = strdup((const char*)message);

		/* Check if the error code is specified in --mysql-ignore-errors, and return
		   DB_ERROR_IGNORABLE if so, or DB_ERROR_FATAL otherwise */
		SB_LIST_FOR_EACH(pos, global_arguments.ignored_errors_list)
		{
			const char* val = SB_LIST_ENTRY(pos, value_t, listitem)->data;

			tmp = (unsigned short)atoi(val);
			if (error == tmp || !strcmp(val, "all"))
			{
				log_text(LOG_DEBUG, "Ignoring error %u %s, ", error, pconn->sql_errmsg);
				*counter = SB_CNT_ERROR;
				return DB_ERROR_IGNORABLE;
			}
		}

		if (query)
			log_text(LOG_FATAL, "%s returned error %u (%s) for query '%s'", location, error, pconn->sql_errmsg, query);
		else
			log_text(LOG_FATAL, "%s returned error %u (%s)", location, error, pconn->sql_errmsg);

		*counter = SB_CNT_ERROR;
		return DB_ERROR_FATAL;
	}

	return DB_ERROR_NONE;
}


//-----------------------------------------------------------------------------
// Name:  register_driver_mssql
//
// Description:
//  Appends the MSSQL driver to the available drivers list.	
//
// Parameters:
//	drivers - list of drivers to append to
//
// Returns:
//	int
//
int register_driver_mssql(sb_list_t* drivers)
{
	SB_LIST_ADD_TAIL(&mssql_driver.listitem, drivers)
	return 0;
}

//-----------------------------------------------------------------------------
// Name:  mssql_drv_init
//
// Description:
//	Initialize the driver.
//
// Parameters:
//
// Returns:
//	int
//
int mssql_driver_init(void)
{
	pthread_mutex_init(&pos_mutex, NULL);

	global_arguments.hosts_list = sb_get_value_list("mssql-host");
	if (SB_LIST_IS_EMPTY(global_arguments.hosts_list))
	{
		log_text(LOG_FATAL, "No MSSQL hosts specified, aborting");
		return 1;
	}
	hosts_pos = SB_LIST_ITEM_NEXT(global_arguments.hosts_list);

	global_arguments.ports = sb_get_value_list("mssql-port");
	if (SB_LIST_IS_EMPTY(global_arguments.ports))
	{
		log_text(LOG_FATAL, "No MSSQL ports specified, aborting");
		return 1;
	}
	ports_pos = SB_LIST_ITEM_NEXT(global_arguments.ports);

	global_arguments.is_debug = sb_get_value_flag("mssql-debug");
	if (global_arguments.is_debug)
	{
		sb_globals.verbosity = LOG_DEBUG;
	}

	global_arguments.database_name = sb_get_value_string("mssql-db");
	global_arguments.use_trusted_authentication = true;
	global_arguments.ignored_errors_list = sb_get_value_list("mssql-ignore-errors");
	global_arguments.is_dry_run = sb_get_value_flag("mssql-dry-run");
	global_arguments.network_packet_size = x_DefaultNetworkPacketSize;
	global_arguments.login_timeout = x_DefaultLoginTimeout;
	if (SQLSetEnvAttr(NULL,
					  SQL_ATTR_CONNECTION_POOLING,
					  (SQLPOINTER)SQL_CP_ONE_PER_DRIVER,
					  SQL_IS_INTEGER) != SQL_SUCCESS)
	{
		get_odbc_error_info(SQL_HANDLE_ENV, global_environment_hdl, "SQLSetEnvAttr");
	}

	if (SQLAllocHandle(SQL_HANDLE_ENV,
					   SQL_NULL_HANDLE,
					   &global_environment_hdl) != SQL_SUCCESS)
	{
		get_odbc_error_info(SQL_HANDLE_ENV, global_environment_hdl, "SQLAllocHandle");
	}

	if (SQLSetEnvAttr(global_environment_hdl,
					  SQL_ATTR_ODBC_VERSION,
					  (SQLPOINTER)SQL_OV_ODBC3,
					  SQL_IS_INTEGER) != SQL_SUCCESS)
	{
		get_odbc_error_info(SQL_HANDLE_ENV, global_environment_hdl, "SQLSetEnvAttr");
	}
	if (SQLSetEnvAttr(NULL,
					  SQL_ATTR_CP_MATCH,
					  (SQLPOINTER)SQL_CP_STRICT_MATCH,
					  SQL_IS_INTEGER) != SQL_SUCCESS)
	{
		get_odbc_error_info(SQL_HANDLE_ENV, global_environment_hdl, "SQLSetEnvAttr");
	}

	return 0;
}

int mssql_driver_on_thread_init(int thread_id)
{
	return 0;
}

static drv_caps_t mssql_driver_capabilities =
{
	1,
	1,
	1,
	0,
	0,
	1
};

int mssql_driver_describe(drv_caps_t* caps)
{
	(*caps) = mssql_driver_capabilities;
	return 0;
}

//-----------------------------------------------------------------------------
// Name:  mssql_connect
//
// Description:
//	Establishes a connection to SQL Server.
//
// Parameters:
//	conn - connection information
//
// Returns:
//	bool
//
static int mssql_connect(mssql_connection_t* db_connection)
{
	if (SQLAllocHandle(SQL_HANDLE_DBC, global_environment_hdl, &db_connection->connection_hdl) != SQL_SUCCESS)
	{
		return get_odbc_error_info(SQL_HANDLE_DBC, db_connection->connection_hdl, "SQLAllocHandle");
	}

	SQLUINTEGER loginTimeout = global_arguments.login_timeout;
	if (SQLSetConnectAttr(db_connection->connection_hdl,
						  SQL_ATTR_LOGIN_TIMEOUT,
						  (SQLPOINTER)loginTimeout,
						  SQL_IS_INTEGER) != SQL_SUCCESS)
	{
		return get_odbc_error_info(SQL_HANDLE_DBC, db_connection->connection_hdl, "SQLSetConnectAttr");
	}

	SQLUINTEGER packetSize = global_arguments.network_packet_size;
	if (SQLSetConnectAttr(db_connection->connection_hdl,
						  SQL_ATTR_PACKET_SIZE,
						  (SQLPOINTER)packetSize,
						  SQL_IS_INTEGER) != SQL_SUCCESS)
	{
		return get_odbc_error_info(SQL_HANDLE_DBC, db_connection->connection_hdl, "SQLSetConnectAttr");
	}

	char szConnectStr[1024] = { '\0' };
	char szServerNameFormat[256] = { '\0' };
	char szAuthFormat[256] = { '\0' };
	char szOutStr[1024] = { '\0' };
	SQLSMALLINT iOutStrLen;
	ULONG retryCount = 0;
	const char* pwszNetwork = NULL;

	if (db_connection->is_named_instance)
	{
		sprintf_s(szServerNameFormat,
				  ARRAYSIZE(szServerNameFormat),
				  x_ServerNameFormatRaw,
				  db_connection->host_name);
	}
	else
	{
		pwszNetwork = x_TcpIpNetwork;

		if (db_connection->is_named_instance)
		{
			sprintf_s(szServerNameFormat,
					  ARRAYSIZE(szServerNameFormat),
					  x_TcpServerNameFormatNI,
					  db_connection->instance_name);
		}
		else
		{
			sprintf_s(szServerNameFormat,
					  ARRAYSIZE(szServerNameFormat),
					  x_TcpServerNameFormat,
					  db_connection->host_name,
					  db_connection->port);
		}
	}

	sprintf_s(szConnectStr,
			  ARRAYSIZE(szConnectStr),
			  x_ConnectionStringFormat,
			  szServerNameFormat,
			  db_connection->database_name,
			  szAuthFormat);

	DEBUG("Connection:  %s", szConnectStr);
	SQLRETURN ret = SQLDriverConnect(
		db_connection->connection_hdl,
		NULL,
		szConnectStr,
		ARRAYSIZE(szConnectStr),
		szOutStr,
		ARRAYSIZE(szOutStr),
		&iOutStrLen,
		SQL_DRIVER_NOPROMPT);

	if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO)
	{
		return get_odbc_error_info(SQL_HANDLE_DBC, db_connection->connection_hdl, "SQLDriverConnect");
	}

	return 0;
}


//-----------------------------------------------------------------------------
// Name:  mssql_drv_connect
//
// Description:
//	Makes a database connection.
//
// Parameters:
//	sb_conn - connection object
//
// Returns:
//	int
//
int mssql_driver_connect(db_conn_t* sb_conn)
{
	mssql_connection_t* db_connection = NULL;

	if (global_arguments.is_dry_run)
		return 0;

	db_connection = mssql_connection_alloc();
	if (db_connection == NULL)
		return 1;

	db_connection->database_name = global_arguments.database_name;
	
	pthread_mutex_lock(&pos_mutex);

	db_connection->host_name = SB_LIST_ENTRY(hosts_pos, value_t, listitem)->data;
	db_connection->port = atoi(SB_LIST_ENTRY(ports_pos, value_t, listitem)->data);

	/*
	  Pick the next port in args.ports. If there are no more ports in the list,
	  move to the next available host and get the first port again.
   */
	ports_pos = SB_LIST_ITEM_NEXT(ports_pos);
	if (ports_pos == global_arguments.ports) {
		hosts_pos = SB_LIST_ITEM_NEXT(hosts_pos);
		if (hosts_pos == global_arguments.hosts_list)
			hosts_pos = SB_LIST_ITEM_NEXT(hosts_pos);

		ports_pos = SB_LIST_ITEM_NEXT(ports_pos);
	}
	pthread_mutex_unlock(&pos_mutex);

	
	if (ERROR_SUCCESS != mssql_connect(db_connection))
	{
		log_text(LOG_FATAL,
				 "unable to connect to MSSQL server on host '%s', port %u, aborting...",
				 db_connection->host_name,
				 db_connection->port);

		free(db_connection);
		return 1;
	}

	// Set output pointer
	sb_conn->ptr = db_connection;

	return 0;
}

int mssql_driver_disconnect(db_conn_t* sb_conn)
{
	mssql_connection_t* db_connection = sb_conn->ptr;

	if (global_arguments.is_dry_run)
	{
		return 0;
	}

	if (db_connection != NULL && db_connection->connection_hdl != NULL)
	{
		DEBUG("SQLDisconnect(%p)", db_connection->connection_hdl);
		if (SQLDisconnect(db_connection->connection_hdl))
		{
			DEBUG("SQLFreeHandle(%p)", db_connection->connection_hdl);
			SQLFreeHandle(SQL_HANDLE_DBC, db_connection->connection_hdl);
		}

		free(db_connection);
	}

	return 0;
}


int get_unique_stmt_name(char* name, int len)
{
	return snprintf(name, len, "sbstmt%d%d",
					(int)sb_rand_uniform_uint64(),
					(int)sb_rand_uniform_uint64());
}

int mssql_driver_prepare(db_stmt_t* stmt, const char* query, size_t len)
{
	char name[32];

	if (global_arguments.is_dry_run)
	{
		return 0;
	}

	mssql_connection_t* db_connection = (mssql_connection_t*)stmt->connection->ptr;
	if (db_connection == NULL || db_connection->connection_hdl == SQL_NULL_HANDLE)
	{
		return 1;
	}

	if (global_use_prepared_statements)
	{
		mssql_statement_t* db_stmt = malloc(sizeof(mssql_statement_t));

		SQLRETURN ret = SQLAllocHandle(SQL_HANDLE_STMT, db_connection->connection_hdl, &db_stmt->statement_hdl);
		if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO)
		{
			return get_odbc_error_info(SQL_HANDLE_DBC, db_connection->connection_hdl, "SQLAllocHandle");
		}

		stmt->ptr = db_stmt;

		DEBUG("SQLPrepare(%p, \"%s\", %u) = %p", db_stmt, query, (unsigned int)len, stmt->ptr);
		ret = SQLPrepare(db_stmt->statement_hdl, (SQLCHAR*)query, SQL_NTS);
		if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO)
		{
			return get_odbc_error_info(SQL_HANDLE_STMT, db_stmt->statement_hdl, "SQLPrepare");
		}

		db_stmt->is_prepared = 1;

		return 0;
	}

	/* Use client-side PS */
	stmt->emulated = 1;
	stmt->query = strdup(query);

	return 0;
}

int mssql_driver_parameter_bind(db_stmt_t* stmt, db_bind_t* params, size_t len)
{
	mssql_statement_t* pstmt;

	if (global_arguments.is_dry_run)
		return 0;

	mssql_connection_t* db_connection = (mssql_connection_t*)stmt->connection->ptr;
	if (db_connection == NULL || db_connection->connection_hdl == SQL_NULL_HANDLE)
		return 1;

	if (stmt->bound_param != NULL)
		free(stmt->bound_param);

	stmt->bound_param = (db_bind_t*)malloc(len * sizeof(db_bind_t));
	if (stmt->bound_param == NULL)
		return 1;

	memcpy(stmt->bound_param, params, len * sizeof(db_bind_t));
	stmt->bound_param_len = (unsigned int)len;

	if (stmt->emulated)
		return 0;

	pstmt = stmt->ptr;
	pstmt->parameter_types = malloc(len * sizeof(mssql_parameter_t));
	if (pstmt->parameter_types == NULL)
		return 1;

	pstmt->parameter_values = (char**)calloc(len, sizeof(char*));
	if (pstmt->parameter_values == NULL)
		return 1;

	/* Allocate buffers for bind parameters */
	for (SQLSMALLINT i = 0; i < len; i++)
	{
		if (pstmt->parameter_values[i] != NULL)
		{
			free(pstmt->parameter_values[i]);
		}

		pstmt->parameter_values[i] = (char*)malloc(MAX_PARAM_LENGTH);
		if (pstmt->parameter_values[i] == NULL)
			return 1;
	}

	/* Convert sysbench data types to PgSQL ones */
	for (SQLSMALLINT i = 0; i < (SQLSMALLINT)len; i++)
	{
		for (i = 0; db_mssql_bind_map[i].db_type != DB_TYPE_NONE; i++)
		{
			if (db_mssql_bind_map[i].db_type == params[i].type)
			{
				pstmt->parameter_types[i].parameter_type = db_mssql_bind_map[i].parameter_type;
				pstmt->parameter_types[i].value_type = db_mssql_bind_map[i].value_type;

				break;
			}
		}

		SQLRETURN ret = SQLBindParameter(pstmt->statement_hdl,
										 i /* parameter number */,
										 pstmt->parameter_types[i].input_output_type,
										 pstmt->parameter_types[i].value_type,
										 pstmt->parameter_types[i].parameter_type,
										 pstmt->parameter_types[i].column_length,
										 0,
										 pstmt->parameter_values[i],
										 0,
										 NULL);

		if (ret != SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO)
		{
			return get_odbc_error_info(SQL_HANDLE_STMT, pstmt->statement_hdl, "SQLBindParameter");
		}
	}

	return 0;
}

int mssql_driver_bind_result(db_stmt_t* stmt, db_bind_t* params, size_t len)
{
	/* NYI */

	(void)stmt;
	(void)params;
	(void)len;

	return 1;
}

db_error_t mssql_driver_execute(db_stmt_t* stmt, db_result_t* rs)
{
	db_conn_t* conn = stmt->connection;
	mssql_connection_t* pmssqlConnection = stmt->connection->ptr;
	mssql_statement_t* pstmt;
	char* buf = NULL;
	unsigned int buflen = 0;
	unsigned int i, j, vcnt;
	char need_realloc;
	int n;
	db_error_t error = DB_ERROR_NONE;

	if (global_arguments.is_dry_run)
		return DB_ERROR_NONE;

	conn->sql_errmsg = NULL;
	conn->sql_errno = 0;
	conn->sql_state = NULL;

	if (!stmt->emulated)
	{
		if (stmt->ptr == NULL)
		{
			log_text(LOG_DEBUG, "ERROR: exiting mysql_drv_execute(), uninitialized statement");
			return DB_ERROR_FATAL;
		}
		pstmt = stmt->ptr;

		SQLRETURN ret = SQLExecute(pstmt->statement_hdl);
		if (ret != SQL_SUCCESS)
		{
			error = get_odbc_error(conn, pstmt, "SQLExecute", stmt->query, &rs->counter);
			goto exit;
		}
	}
	else
	{
		need_realloc = 1;
		vcnt = 0;
		for (i = 0, j = 0; stmt->query[i] != '\0'; i++)
		{
		again:
			if (j + 1 >= buflen || need_realloc)
			{
				buflen = (buflen > 0) ? buflen * 2 : 256;
				buf = realloc(buf, buflen);
				if (buf == NULL)
					return DB_ERROR_FATAL;
				need_realloc = 0;
			}

			if (stmt->query[i] != '?')
			{
				buf[j++] = stmt->query[i];
				continue;
			}

			n = db_print_value(stmt->bound_param + vcnt, buf + j, buflen - j);
			if (n < 0)
			{
				need_realloc = 1;
				goto again;
			}
			j += n;
			vcnt++;
		}
		buf[j] = '\0';

		HSTMT hstmt = SQL_NULL_HANDLE;
		SQLRETURN ret = SQLAllocHandle(SQL_HANDLE_STMT, pmssqlConnection->connection_hdl, &hstmt);
		if (ret != SQL_SUCCESS)
		{
			error = get_odbc_error(pmssqlConnection, NULL, "SQLAllocHandle", buf, NULL);
			goto exit;
		}

		ret = SQLExecDirect(hstmt, (SQLCHAR*)buf, SQL_NTS);
		if (ret != SQL_SUCCESS)
		{
			get_odbc_error_info(SQL_HANDLE_STMT, hstmt, "SQLExecDirect");
			ret = DB_ERROR_FATAL;
			goto exit;
		}
	}

exit:
	if (buf != NULL)
	{
		free(buf);
	}

	return error;
}

int mssql_driver_fetch(db_result_t* result)
{
	return 0;
}

int mssql_driver_fetch_row(db_result_t* result, db_row_t* row)
{
	return 0;
}

#define xfree(ptr) do{ if (ptr) free((void *)ptr); ptr = NULL; }while(0)

db_error_t mssql_driver_query_exec(db_conn_t* connection, const char* query, size_t length, db_result_t* result)
{
	mssql_connection_t* pconn = connection->ptr;
	db_error_t rc = DB_ERROR_NONE;
	SQLHSTMT hstmt = SQL_NULL_HANDLE;

	(void)length; /* unused */

	connection->sql_errno = 0;
	xfree(connection->sql_state);
	xfree(connection->sql_errmsg);

	SQLRETURN ret = SQLAllocHandle(SQL_HANDLE_STMT, pconn->connection_hdl, &hstmt);
	if (ret != SQL_SUCCESS)
	{
		rc = get_odbc_error(connection, NULL, "SQLAllocHandle", query, NULL);
		goto exit;
	}

	ret = SQLExecDirect(hstmt, (SQLCHAR*)query, SQL_NTS);
	if (ret != SQL_SUCCESS)
	{
		rc = get_odbc_error(connection, NULL, "SQLExecDirect", query, NULL);
		goto exit;
	}

	result->ptr = (result->counter == SB_CNT_READ) ? (void*)ret : NULL;

exit:
	if (hstmt != SQL_NULL_HANDLE)
		SQLFreeStmt(hstmt, 0);

	return rc;
}


int mssql_driver_results_free(db_result_t* result)
{
	return 0;
}

int mssql_driver_close(db_stmt_t* stmt)
{
	return 0;
}

int mssql_driver_on_thread_done(int thread_id)
{
	return 0;
}

int mssql_driver_finished()
{
	return 0;
}
