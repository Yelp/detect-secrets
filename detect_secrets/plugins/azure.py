"""
This plugin searches for Azure keys/connection strings.
"""
import re

from detect_secrets.plugins.base import RegexBasedDetector


class AzureKeyDetector(RegexBasedDetector):
    """Scans for Azure keys/connection strings."""
    secret_type = 'Azure keys/connection strings'

    denylist = [
        # Azure Storage - account access key
        # Example: DefaultEndpointsProtocol=https;AccountName=<account_name>;AccountKey=<account_key>;EndpointSuffix=core.windows.net
        # https://docs.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string
        re.compile(r'AccountName=.+;.*AccountKey=[a-zA-Z0-9+/=]{88}'),

        # Azure SQL Database - ADO.NET connection string
        # Example: Server=tcp:<server_name>.database.windows.net,1433;Initial Catalog=<database_name>;Persist Security Info=False;User ID=<user_name>;Password=<password>;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;
        # https://docs.microsoft.com/en-us/azure/azure-sql/database/connect-query-content-reference-guide
        # https://docs.microsoft.com/en-us/azure/azure-sql/database/logins-create-manage
        re.compile(r'Server=tcp:.+\.database\.windows\.net.+Password=[^;]{8,128};'),

        # Azure SQL Database - JDBC connection string
        # Example: jdbc:sqlserver://<server_name>.database.windows.net:1433;database=<database_name>;user=<user_name>@<server_name>;password=<password>;encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.database.windows.net;loginTimeout=30;
        re.compile(r'jdbc:sqlserver://.+\.database\.windows\.net.+password=[^;]{8,128};'),

        # Azure SQL Database - ODBC connection string
        # Example: Driver={ODBC Driver 13 for SQL Server};Server=tcp:<server_name>.database.windows.net,1433;Database=<database_name>;Uid=<user_name>;Pwd=<password>;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;
        re.compile(r'Driver=\{ODBC Driver.+SQL Server\};.+\.database\.windows\.net.+Pwd=[^;]{8,128};'),

        # Azure Database for PostgreSQL - PostgreSQL connection URL
        # Example: postgresql://<user_name>:<password>@<server_name>.postgres.database.azure.com/<database_name>?sslmode=require
        # Example: postgres://<user_name>:<password>@<server_name>.postgres.database.azure.com/<database_name>?sslmode=require
        # https://docs.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-servers
        re.compile(r'postgres(|ql)://.+:\S{8,128}@.+\.postgres\.database\.azure\.com'),

        # Azure Database for PostgreSQL - JDBC connection string
        # Example: jdbc:postgresql://<server_name>.postgres.database.azure.com:5432/<database_name>?user=<user_name>&password=<password>&sslmode=require
        re.compile(r'jdbc:postgresql://.+\.postgres\.database\.azure\.com.+password=[^&]{8,128}'),

        # Azure Database for PostgreSQL - Node.js, Python, Ruby, PHP, C++ (libpq) connection string
        # Example: host=<server>.postgres.database.azure.com port=5432 dbname=<database_name> user=<user_name> password=<password> sslmode=require
        re.compile(r'host=.+\.postgres\.database\.azure\.com.+password=\S{8,128}'),

        # Azure Database for PostgreSQL - ADO.NET connection string
        # Example: Server=<server_name>.postgres.database.azure.com;Database=<database_name>;Port=5432;User Id=<user_name>;Password=<password>;Ssl Mode=Require;
        re.compile(r'Server=.+\.postgres\.database\.azure\.com.*Password=[^;]{8,128};'),

        # Azure Database for MySQL - ADO.NET connection string
        # Example: Server="<server_name>.mysql.database.azure.com";UserID="<user_name>";Password="<password>";Database="<database_name>";SslMode=MySqlSslMode.Required;SslCa="<file_path>";
        # https://docs.microsoft.com/en-us/azure/mysql/flexible-server/quickstart-create-server-portal#connect-to-the-server
        re.compile(r'Server=.+\.mysql\.database\.azure\.com.+Password="[^"]{8,128}";'),

        # Azure Database for MariaDB - ADO.NET connection string
        # Example: Server=<server_name>.mariadb.database.azure.com; Port=3306; Database=<database_name>; Uid=<user_name>@<server_name>; Pwd=<password>; SslMode=Preferred;
        # https://docs.microsoft.com/en-us/azure/mariadb/howto-connection-string
        re.compile(r'Server=.+\.mariadb\.database\.azure\.com.+Pwd=[^;]{8,128};'),

        # Azure Cache for Redis - StackExchange.Redis connection string
        # Example: <server_name>.redis.cache.windows.net:6380,password=<access_key>,ssl=True,abortConnect=False
        # https://docs.microsoft.com/en-us/azure/azure-cache-for-redis/cache-web-app-howto
        re.compile(r'.+\.redis\.cache\.windows\.net.+password=[a-zA-Z0-9=]{44}'),

        # Azure Cosmos DB - SQL/Core API - connection string
        # Example: AccountEndpoint=https://<server_name>.documents.azure.com:443/;AccountKey=<account_key>;
        # Azure Cosmos DB - Gremlin API - connection string
        # Example: AccountEndpoint=https://<server_name>.documents.azure.com:443/;AccountKey=<account_key>;ApiKind=Gremlin;
        # https://docs.microsoft.com/en-us/azure/cosmos-db/secure-access-to-data
        re.compile(r'AccountEndpoint=https://.+\.documents\.azure\.com.+AccountKey=[a-zA-Z0-9=]{88};'),

        # Azure Cosmos DB - MongoDB API - connection string
        # Example: mongodb://<user_name>:<password>@<server_name>.mongo.cosmos.azure.com:10255/?ssl=true&replicaSet=globaldb&retrywrites=false&maxIdleTimeMS=120000&appName=@mongoneo@
        re.compile(r'mongodb://.+:[a-zA-Z0-9=]{88}@.+\.mongo\.cosmos\.azure\.com'),

        # Azure Cosmos DB - Cassandra API - connection string
        # Example: HostName=<server_name>.cassandra.cosmos.azure.com;Username=<user_name>;Password=<passwprd>;Port=10350
        re.compile(r'HostName=.+\.cassandra\.cosmos\.azure\.com;.*Password=[a-zA-Z0-9=]{88};'),

        # Azure Synapse Analytics - SQL pool - ADO.NET connection string
        # Example: Server=tcp:<server_name>.sql.azuresynapse.net,1433;Initial Catalog=<database_name>;Persist Security Info=False;User ID=<user_name>;Password=<password>;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;
        # https://docs.microsoft.com/en-us/azure/synapse-analytics/sql/connect-overview
        re.compile(r'Server=tcp:.+\.azuresynapse\.net.+Password=[^;]{8,128};'),

        # Azure Synapse Analytics - SQL pool - JDBC connection string
        # Example: jdbc:sqlserver://<server_name>.sql.azuresynapse.net:1433;database=<database_name>;user=<username>@<server_name>;password=<password>;encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.sql.azuresynapse.net;loginTimeout=30;
        re.compile(r'jdbc:sqlserver://.+\.azuresynapse\.net.+password=[^;]{8,128};'),

        # Azure Synapse Analytics - SQL pool - ODBC connection string
        # Example: Driver={ODBC Driver 13 for SQL Server};Server=tcp:<server_name>.sql.azuresynapse.net,1433;Database=<database_name>;Uid=<user_name>;Pwd=<password>;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;
        re.compile(r'Driver=\{ODBC Driver.+SQL Server\};.+\.azuresynapse\.net.+Pwd=[^;]{8,128};'),

        # Azure Service Bus/Azure Event Hubs - connection string
        # Example: Endpoint=sb://<server_name>.servicebus.windows.net/;SharedAccessKeyName=<shared_access_key_name>;SharedAccessKey=<shared_access_key>
        # Example: Endpoint=sb://<server_name>.servicebus.windows.net/;SharedAccessKeyName=<shared_access_key_name>;SharedAccessKey=<shared_access_key>;EntityPath=<event_hub_name>
        # https://docs.microsoft.com/en-us/azure/service-bus-messaging/service-bus-dotnet-get-started-with-queues
        # https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string
        re.compile(r'Endpoint=sb://.+\.servicebus\.windows\.net/;.*SharedAccessKey=[a-zA-Z0-9+/=]{44}'),

        # Azure IoT Hub - device connection string
        # Example: HostName=<server_name>.azure-devices.net;DeviceId=<device_id>;SharedAccessKey=<shared_access_key>
        # https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-dev-guide-sas
        re.compile(r'HostName=.+\.azure-devices\.net;DeviceId=.+;SharedAccessKey=[a-zA-Z0-9+/=]{44}'),

        # Azure IoT Hub - service connection string
        # Example: HostName=<server_name>.azure-devices.net;SharedAccessKeyName=<share_access_key_name>;SharedAccessKey=<share_access_key>
        re.compile(r'HostName=.+\.azure-devices\.net;SharedAccessKeyName=.+;SharedAccessKey=[a-zA-Z0-9+/=]{44}'),

        # Azure Monitor - Application Insights - connection string
        # Example: InstrumentationKey=343d6e27-f0e4-415c-ba09-afc023c61a45;IngestionEndpoint=<ingestion_endpoint_url>;LiveEndpoint=<live_endpoint_url>
        # https://docs.microsoft.com/en-us/azure/azure-monitor/app/sdk-connection-string
        re.compile(r'InstrumentationKey=[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'),

        # Azure Functions - HTTP trigger - API key
        # Example: https://<app_name>.azurewebsites.net/api/<function_name>?code=<api_key>
        # https://docs.microsoft.com/en-us/azure/azure-functions/functions-bindings-http-webhook-trigger#api-key-authorization
        # https://docs.microsoft.com/en-us/azure/azure-functions/security-concepts#function-access-keys
        re.compile(r'https://[a-zA-Z0-9\-]{2,60}.azurewebsites.net/api/[a-zA-Z0-9_\-]{1,128}\?code=[a-zA-Z0-9_=\-]{56}'),

        # Azure Web PubSub - connection string
        # Example: Endpoint=https://<server_name>.webpubsub.azure.com;AccessKey=<access_key>;Version=1.0;
        # https://docs.microsoft.com/en-us/azure/azure-web-pubsub/quickstart-use-sdk
        re.compile(r'Endpoint=https://.+webpubsub\.azure\.com;.*AccessKey=[a-zA-Z0-9+/=]{44}'),

        # Azure SignalR Service - connection string
        # Example: Endpoint=https://<server_name>.service.signalr.net;AccessKey=<access_key>;Version=1.0;
        # https://docs.microsoft.com/en-us/azure/azure-signalr/concept-connection-string
        re.compile(r'Endpoint=https://.+\.service\.signalr\.net;.*AccessKey=[a-zA-Z0-9+/=]{44}'),
    ]
