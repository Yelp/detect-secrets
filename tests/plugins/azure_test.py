import pytest

from detect_secrets.plugins.azure import AzureKeyDetector


class TestAzureKeyDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            (
                'DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==;EndpointSuffix=core.windows.net',  # noqa: E501
                True,
            ),
            (
                'Server=tcp:myserver.database.windows.net,1433;Initial Catalog=database;Persist Security Info=False;User ID=myusername;Password=mypassword;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;',  # noqa: E501
                True,
            ),
            (
                'jdbc:sqlserver://myserver.database.windows.net:1433;database=mydatabase;user=myusername@myserver;password=mypassword;encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.database.windows.net;loginTimeout=30;',  # noqa: E501
                True,
            ),
            (
                'Driver={ODBC Driver 13 for SQL Server};Server=tcp:myserver.database.windows.net,1433;Database=mydatabase;Uid=myusername;Pwd=mypassword;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;',  # noqa: E501
                True,
            ),
            (
                'postgresql://myusername:mypassword@myserver.postgres.database.azure.com/mydatabase?sslmode=require',  # noqa: E501
                True,
            ),
            (
                'postgres://myusername:mypassword@myserver.postgres.database.azure.com/mydatabase?sslmode=require',  # noqa: E501
                True,
            ),
            (
                'jdbc:postgresql://myserver.postgres.database.azure.com:5432/mydatabase?user=myusername&password=mypassword&sslmode=require',  # noqa: E501
                True,
            ),
            (
                'host=myserver.postgres.database.azure.com port=5432 dbname=mydatabase user=myusername password=mypassword sslmode=require',  # noqa: E501
                True,
            ),
            (
                'Server=myserver.postgres.database.azure.com;Database=mydatabase;Port=5432;User Id=myusername;Password=mypassword;Ssl Mode=Require;',  # noqa: E501
                True,
            ),
            (
                'Server="myserver.mysql.database.azure.com";UserID="myusername";Password="mypassword";Database="mydatabase";SslMode=MySqlSslMode.Required;SslCa="/dir/file";',  # noqa: E501
                True,
            ),
            (
                'Server=myserver.mariadb.database.azure.com; Port=3306; Database=mydatabase; Uid=myusername@myserver; Pwd=mypassword; SslMode=Preferred;',  # noqa: E501
                True,
            ),
            (
                'myserver.redis.cache.windows.net:6380,password=ANUoYtxKnsjCIiZqBjxRVZW2tL44inYFXAzCaI3moro=,ssl=True,abortConnect=False',  # noqa: E501
                True,
            ),
            (
                'AccountEndpoint=https://myserver.documents.azure.com:443/;AccountKey=8LxIR3Q38aXIkbpR7Zww7CcZnw0qVyqV6zl9iZUQJiayLeSHjIIn6uNfFrWaHJlXdxXmf8SZCfYUb5p07zTzBg==;',  # noqa: E501
                True,
            ),
            (
                'AccountEndpoint=https://myserver.documents.azure.com:443/;AccountKey=8LxIR3Q38aXIkbpR7Zww7CcZnw0qVyqV6zl9iZUQJiayLeSHjIIn6uNfFrWaHJlXdxXmf8SZCfYUb5p07zTzBg==;ApiKind=Gremlin;',  # noqa: E501
                True,
            ),
            (
                'mongodb://myusername:8LxIR3Q38aXIkbpR7Zww7CcZnw0qVyqV6zl9iZUQJiayLeSHjIIn6uNfFrWaHJlXdxXmf8SZCfYUb5p07zTzBg==@myserver.mongo.cosmos.azure.com:10255/?ssl=true&replicaSet=globaldb&retrywrites=false&maxIdleTimeMS=120000&appName=@myserver@',  # noqa: E501
                True,
            ),
            (
                'HostName=myserver.cassandra.cosmos.azure.com;Username=myusername;Password=8LxIR3Q38aXIkbpR7Zww7CcZnw0qVyqV6zl9iZUQJiayLeSHjIIn6uNfFrWaHJlXdxXmf8SZCfYUb5p07zTzBg==;Port=10350',  # noqa: E501
                True,
            ),
            (
                'Server=tcp:myserver.sql.azuresynapse.net,1433;Initial Catalog=mydatabase;Persist Security Info=False;User ID=myusername;Password=mypassword;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;',  # noqa: E501
                True,
            ),
            (
                'jdbc:sqlserver://myserver.sql.azuresynapse.net:1433;database=mydatabase;user=myusername@myserver;password=mypassword;encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.sql.azuresynapse.net;loginTimeout=30;',  # noqa: E501
                True,
            ),
            (
                'Driver={ODBC Driver 13 for SQL Server};Server=tcp:myserver.sql.azuresynapse.net,1433;Database=mydatabase;Uid=myusername;Pwd=mypassword;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;',  # noqa: E501
                True,
            ),
            (
                'Endpoint=sb://myserver.servicebus.windows.net/;SharedAccessKeyName=mysharedaccesskey;SharedAccessKey=+Fsj4wg3tlSG13jrz+Sbz4Qn/Ku7x2DZ/BIub6+myvI=',  # noqa: E501
                True,
            ),
            (
                'Endpoint=sb://myserver.servicebus.windows.net/;SharedAccessKeyName=mysharedaccesskey;SharedAccessKey=+Fsj4wg3tlSG13jrz+Sbz4Qn/Ku7x2DZ/BIub6+myvI=;EntityPath=myeventhub',  # noqa: E501
                True,
            ),
            (
                'HostName=myserver.azure-devices.net;DeviceId=mydeviceid;SharedAccessKey=y9M6/nHrmNoXI3c4q0h51scdhKGJhm05xe7goNbVJiw=',  # noqa: E501
                True,
            ),
            (
                'HostName=myserver.azure-devices.net;SharedAccessKeyName=mysharedaccesskey;SharedAccessKey=83DTl0aasjLNkzaw8/YN1ZDixf9yTU+SRAIKm8F4QEs=',  # noqa: E501
                True,
            ),
            (
                'InstrumentationKey=343d6e27-f0e4-415c-ba09-afc023c61a45;IngestionEndpoint=https://japanwest-0.in.applicationinsights.azure.com/;LiveEndpoint=https://japanwest.livediagnostics.monitor.azure.com/',  # noqa: E501
                True,
            ),
            (
                'https://myserver.azurewebsites.net/api/myfunction?code=O97nV6v3n5qw8vvhpsxjv_9xcEKIyCzpcI6rCqX3lgkXAzFunQTFHw==',  # noqa: E501
                True,
            ),
            (
                'Endpoint=https://myserver.webpubsub.azure.com;AccessKey=8zPs2pLknmmJ1xJZU/prH+/se1YLaNjISlTqFuCELKM=;Version=1.0;',  # noqa: E501
                True,
            ),
            (
                'Endpoint=https://myserver.service.signalr.net;AccessKey=E6JasoxBE0fu8L7Y6WnX+6I35OaRm4Pbf3fXOW2m+d4=;Version=1.0;',  # noqa: E501
                True,
            ),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = AzureKeyDetector()
        assert logic.analyze_line(filename='mock_filename', line=payload)
