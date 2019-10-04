## Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: BSD-3-Clause

##! Implements base functionality for TDS analysis.
##! Generates the tds.log file, containing some information about the TDS headers.
##! Generates the tds_sql_batch.log file, containing some information about the TDS device.

module TDS;

export {
    redef enum Log::ID += {
        Log_TDS,
        Log_TDS_RPC,
        Log_TDS_SQL_Batch
        };

    ## header info
    type TDS: record {
        ts      : time &log;                ## Timestamp for when the event happened.
        uid     : string &log;              ## Unique ID for the connection.
        id      : conn_id &log;             ## The connection's 4-tuple of endpoint addresses/ports.

        command : string &optional &log;    ## Name of the sent TDS command.
        };
    ## Event that can be handled to access the tds record as it is sent to the loggin framework.
    global log_tds: event(rec: TDS);

    ## Remote Procedure Call
    type TDS_RPC: record {
        ts              : time &log;                ## Timestamp for when the event happened.
        uid             : string &log;              ## Unique ID for the connection.
        id              : conn_id &log;             ## The connection's 4-tuple of endpoint addresses/ports.

        procedure_name  : string &optional &log;
        parameters      : string_vec &optional &log;
        };
    ## Event that can be handled to access the tds record as it is sent to the loggin framework.
    global log_tds_rpc: event(rec: TDS_RPC);

    ## SQL Batch
    type TDS_SQL_Batch: record {
        ts          : time &log;                ## Timestamp for when the event happened.
        uid         : string &log;              ## Unique ID for the connection.
        id          : conn_id &log;             ## The connection's 4-tuple of endpoint addresses/ports.

        header_type : string &optional &log;
        query       : string &optional &log;
        };
    ## Event that can be handled to access the tds record as it is sent to the loggin framework.
    global log_tds_sql_batch: event(rec: TDS_SQL_Batch);
    }

redef record connection += {
    tds             : TDS &optional;
    tds_rpc         : TDS_RPC &optional;
    tds_sql_batch   : TDS_SQL_Batch &optional;
    };

## define listening ports
const ports = {
    1433/tcp
    };
redef likely_server_ports += {
    ports
    };

event zeek_init() &priority=5 {
    Log::create_stream(TDS::Log_TDS,
                        [$columns=TDS,
                        $ev=log_tds,
                        $path="tds"]);
    Log::create_stream(TDS::Log_TDS_RPC,
                        [$columns=TDS_RPC,
                        $ev=log_tds_rpc,
                        $path="tds_rpc"]);
    Log::create_stream(TDS::Log_TDS_SQL_Batch,
                        [$columns=TDS_SQL_Batch,
                        $ev=log_tds_sql_batch,
                        $path="tds_sql_batch"]);
    Analyzer::register_for_ports(Analyzer::ANALYZER_TDS, ports);
    }

##! general tds header
event tds(c: connection, is_orig: bool, command: count) {
    if(!c?$tds) {
        c$tds = [$ts=network_time(), $uid=c$uid, $id=c$id];
        }

    c$tds$ts = network_time();
    c$tds$command = commands[command];

    Log::write(Log_TDS, c$tds);
    delete c$tds;
    }

##! general tds rpc
event tds_rpc(c: connection, is_orig: bool,
        procedure_name: string,
        parameters: string) {
    if(!c?$tds_rpc) {
        c$tds_rpc = [$ts=network_time(), $uid=c$uid, $id=c$id];
        }

    c$tds_rpc$ts = network_time();
    c$tds_rpc$procedure_name = subst_string(procedure_name, "\x00", "");
    local params_size: count = |parameters|;
    if (params_size > 0) {
        local params: string_vec;
        local params_index: count=0;
        local param_index: count=0;
        local param_name: string="";
        local param_type: count=0;
        local param_data: string;
        local param_len: count=0;
        while (param_index < params_size) {
            param_len = bytestring_to_count(parameters[param_index])*2;
            param_index += 1;
            param_name = subst_string(parameters[param_index: param_index+param_len], "\x00", "");
            param_index += param_len;
            param_index += 1; ##! status
            param_type = bytestring_to_count(parameters[param_index]);
            param_index += 1;
            param_data = "";
            switch (param_type) {
                case 0x24, ##! GUID
                    0x26, ##! int
                    0x68, ##! bit
                    0x6d, ##! float
                    0x6f: ##! DateTime
                    param_index += 1; ##! max length
                    param_len = bytestring_to_count(parameters[param_index]);
                    param_index += 1;
                    switch (param_type) {
                        case 0x24: ##! GUID
                            param_data = bytestring_to_hexstr(parameters[param_index+3]);
                            param_data += bytestring_to_hexstr(parameters[param_index+2]);
                            param_data += bytestring_to_hexstr(parameters[param_index+1]);
                            param_data += bytestring_to_hexstr(parameters[param_index]);
                            param_data += "-";
                            param_data += bytestring_to_hexstr(parameters[param_index+5]);
                            param_data += bytestring_to_hexstr(parameters[param_index+4]);
                            param_data += "-";
                            param_data += bytestring_to_hexstr(parameters[param_index+7]);
                            param_data += bytestring_to_hexstr(parameters[param_index+6]);
                            param_data += "-";
                            param_data += bytestring_to_hexstr(parameters[param_index+8:param_index+10]);
                            param_data += "-";
                            param_data += bytestring_to_hexstr(parameters[param_index+10:param_index+param_len]);
                            break;
                        case 0x68: ##! bit
                            if (bytestring_to_count(parameters[param_index]) == 1) {
                                param_data = "True";
                                }
                            else {
                                param_data = "False";
                                }
                            break;
                        case 0x6d: ##! float
                            param_data = fmt("%f", bytestring_to_double(parameters[param_index:param_index+param_len]));
                            break;
                        default:
                            if (param_index >= params_size) {
                                break;
                                }
                            param_data = fmt("%d", bytestring_to_count(parameters[param_index:param_index+param_len], T));
                            break;
                        }
                    param_index += param_len;
                    params[params_index] = fmt("%s=%s", param_name, param_data);
                    params_index += 1;
                    break;
                case 0xe7: ##! NVarChar
                    param_index += 2; ##! max length
                    param_index += 5; ##! collation
                    param_len = bytestring_to_count(parameters[param_index:param_index+2], T);
                    param_index += 2;
                    ##! NULL is 65535
                    if (param_len > 0 && param_len < 65535) {
                        param_data = subst_string(parameters[param_index:param_index+param_len], "\x00", "");
                        param_index += param_len;
                        }
                    params[params_index] = fmt("%s=%s", param_name, param_data);
                    params_index += 1;
                    break;
                }
            }

        c$tds_rpc$parameters = params;
        }

    Log::write(Log_TDS_RPC, c$tds_rpc);
    delete c$tds_rpc;
    }

event tds_sql_batch(c: connection, is_orig: bool,
            header_type: count,
            query: string) {
    if(!c?$tds_sql_batch) {
        c$tds_sql_batch = [$ts=network_time(), $uid=c$uid, $id=c$id];
        }

    c$tds_sql_batch$ts = network_time();
    c$tds_sql_batch$header_type = header_types[header_type];
    query = subst_string(query, "\x00", "");
    c$tds_sql_batch$query = query;

    Log::write(Log_TDS_SQL_Batch, c$tds_sql_batch);
    delete c$tds_sql_batch;
    }

event connection_state_remove(c: connection) &priority=-5 {
    if(c?$tds) {
        delete c$tds;
        }
    }
