using System;
using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json;
using NLog;
using Nest;
using Newtonsoft.Json.Linq;
using Elasticsearch.Net;

namespace LogFlow.Builtins.Outputs
{
    public class ElasticSearchOutput : LogProcessor
    {
        private static readonly Logger Log = LogManager.GetCurrentClassLogger();
        private readonly ElasticSearchConfiguration _configuration;
        private readonly HashSet<string> _indexNames = new HashSet<string>();
        private readonly ElasticClient _client;
        private readonly JsonSerializer _serializer;

        public ElasticSearchOutput(ElasticSearchConfiguration configuration)
        {
            _configuration = configuration;
            var clientSettings = configuration.CreateConnectionFromSettings();
            _client = new ElasticClient(clientSettings);

            _serializer = new JsonSerializer();
            _serializer.DateFormatHandling = DateFormatHandling.IsoDateFormat;
            _serializer.DateFormatString = "yyyy'-'MM'-'dd'T'HH':'mm':'ss.fffffffK";
        }

        public ElasticSearchOutput(ElasticSearchConfiguration configuration, ConnectionSettings clientSettings)
        {
            _configuration = configuration;
            _client = new ElasticClient(clientSettings);
            _serializer = new JsonSerializer();
            _serializer.DateFormatHandling = DateFormatHandling.IsoDateFormat;
            _serializer.DateFormatString = "yyyy'-'MM'-'dd'T'HH':'mm':'ss.fffffffK";
        }

        private void IndexLog(string jsonBody, DateTime timestamp, string logType, string lineId)
        {
            var indexName = BuildIndexName(timestamp).ToLowerInvariant();
            EnsureIndexExists(indexName);
            var indexResult = _client.LowLevel.IndexPut<string>(indexName, logType, lineId, jsonBody);
            //var indexResult = _client.LowLevel (indexName, logType, lineId, jsonBody);

            if (!indexResult.Success)
            {
                throw new ApplicationException(string.Format("Failed to index: '{0}'. Response: '{1}'.", jsonBody, indexResult.Body));
            }

            Log.Trace("{0}: ({1}) Indexed successfully.", LogContext.LogType, lineId);
        }

        private string BuildIndexName(DateTime timestamp)
        {
            var prefix = timestamp.ToString(_configuration.IndexNameFormat);
            return prefix + Math.Floor(timestamp.Day / 6m);
        }

        private void EnsureIndexExists(string indexName)
        {
            if (_indexNames.Contains(indexName))
                return;

            CreateIndex(indexName);
            _indexNames.Add(indexName);
        }


        private void CreateIndex(string indexName)
        {
            if (_client.IndexExists(indexName).Exists)
                return;


            var createIndexRequest = new CreateIndexRequest(indexName)
            {

            };


            var result = _client.CreateIndex(createIndexRequest);

            CreateMappings(indexName);

            if (!result.Acknowledged)
            {
                throw new ApplicationException(string.Format("Failed to create index: '{0}'. Result: '{1}'", indexName, result.ServerError.Error.Reason));
            }

            Log.Trace("{0}: Index '{1}' i successfully created.", LogContext.LogType, indexName);
        }

        private void CreateMappings(string indexName)
        {
            var descriptor = new PutMappingDescriptor<IIsLog>(indexName, LogContext.LogType).AutoMap();
            var result = _client.Map(descriptor);


            if (!result.Acknowledged)
            {
                throw new ApplicationException(string.Format("Failed to update mapping for index: '{0}'. Result: '{1}'", indexName, result.ServerError.Error.Reason));
            }
        }

        public override Result Process(Result result)
        {
            if (result.EventTimeStamp == null)
            {
                throw new ArgumentNullException(ElasticSearchFields.Timestamp);
            }

            var jsonTimeStamp = new JValue(result.EventTimeStamp);
            if (result.Json[ElasticSearchFields.Timestamp] == null)
            {
                result.Json.Add(ElasticSearchFields.Timestamp, jsonTimeStamp);
            }
            else
            {
                result.Json[ElasticSearchFields.Timestamp] = jsonTimeStamp;
            }

            var messageProperty = result.Json[ElasticSearchFields.Message] as JValue;
            if (messageProperty == null || string.IsNullOrWhiteSpace(messageProperty.Value.ToString()))
            {
                messageProperty = new JValue(result.Line);
                result.Json[ElasticSearchFields.Message] = messageProperty;
            }

            var lineId = result.Id.ToString();
            //result.Json[ElasticSearchFields.Id] = new JValue(lineId);
            //result.Json[ElasticSearchFields.Type] = new JValue(LogContext.LogType);
            //result.Json[ElasticSearchFields.Source] = new JValue(Environment.MachineName);

            if (!string.IsNullOrWhiteSpace(_configuration.Ttl))
            {
                result.Json[ElasticSearchFields.TTL] = new JValue(_configuration.Ttl);
            }
            string json;
            using (var writer = new StringWriter())
            {
                _serializer.Serialize(writer, result.Json);
                json = writer.ToString();
            }
            IndexLog(json, result.EventTimeStamp.Value, LogContext.LogType, lineId);
            return result;
        }

        public class IIsLog
        {

            [Ip(Name = "c-ip")]
            public string CIP { get; set; }

            [Ip(Name = "s-ip")]
            public string SIP { get; set; }

            [String(Name = "cs(Cookie)", Index = FieldIndexOption.NotAnalyzed)]
            public string CsCookie { get; set; }

            [String(Name = "cs(Referer)", Index = FieldIndexOption.NotAnalyzed)]
            public string CsReferer { get; set; }

            [String(Name = "cs(User-Agent)", Index = FieldIndexOption.NotAnalyzed)]
            public string CsUserAgent { get; set; }

            [String(Name = "cs-host", Index = FieldIndexOption.NotAnalyzed)]
            public string CsHost { get; set; }

            [String(Name = "cs-method", Index = FieldIndexOption.NotAnalyzed)]
            public string CsMethod { get; set; }

            [String(Name = "cs-uri-query", Index = FieldIndexOption.NotAnalyzed)]
            public string CsUriQuery { get; set; }

            [String(Name = "cs-uri-stem", Index = FieldIndexOption.NotAnalyzed)]
            public string CsUriStem { get; set; }

        }
    }
}
