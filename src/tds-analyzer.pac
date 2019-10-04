## Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: BSD-3-Clause

connection TDS_Conn(bro_analyzer: BroAnalyzer) {
    upflow   = TDS_Flow(true);
    downflow = TDS_Flow(false);
    };

%header{
    #define SQL_BATCH        0x01
    #define PRE_TDS7_LOGIN        0x02
    #define REMOTE_PROCEDURE_CALL    0x03
    #define RESPONSE        0x04
    #define UNUSED            0x05
    #define ATTENTION_REQUEST    0x06
    #define BULK_LOAD_DATA        0x07
    #define TRANSACTION_MANAGER    0x0e
    #define TDS5_QUERY        0x0F
    #define TDS7_LOGIN        0x10
    #define SSPI_MESSAGE        0x11
    #define TDS7_PRELOGIN        0x12
    
    #define QUERY_NOTIFICATIONS    0x0001
    #define TRANSACTION_DESCRIPTOR    0x0002
    %}

flow TDS_Flow(is_orig: bool) {
    # flowunit ?
    datagram = TDS_PDU(is_orig) withcontext(connection, this);
    
    function tds(header: TDS): bool %{
        if(::tds) {
            if (${header.command} != SQL_BATCH &&
                ${header.command} != PRE_TDS7_LOGIN &&
                ${header.command} != REMOTE_PROCEDURE_CALL &&
                ${header.command} != RESPONSE &&
                ${header.command} != UNUSED &&
                ${header.command} != ATTENTION_REQUEST &&
                ${header.command} != BULK_LOAD_DATA &&
                ${header.command} != TRANSACTION_MANAGER &&
                ${header.command} != TDS5_QUERY &&
                ${header.command} != TDS7_LOGIN &&
                ${header.command} != SSPI_MESSAGE &&
                ${header.command} != TDS7_PRELOGIN) {
                return false;
                }
            connection()->bro_analyzer()->ProtocolConfirmation();
            BifEvent::generate_tds(connection()->bro_analyzer(),
                            connection()->bro_analyzer()->Conn(),
                            is_orig(),
                            ${header.command}
                            );
            }

        return true;
        %}

    function tds_rpc(rpc: TDS_RPC): bool %{
        if(::tds_rpc) {
            connection()->bro_analyzer()->ProtocolConfirmation();
            BifEvent::generate_tds_rpc(connection()->bro_analyzer(),
                            connection()->bro_analyzer()->Conn(),
                            is_orig(),
                            bytestring_to_val(${rpc.procedure_name}),
                            bytestring_to_val(${rpc.parameters})
                            );
            }

        return true;
        %}

    function tds_sql_batch(sqlBatch: TDS_SQL_BATCH): bool %{
        if(::tds_sql_batch) {
            if (${sqlBatch.stream_header.header_type} != QUERY_NOTIFICATIONS &&
                ${sqlBatch.stream_header.header_type} != TRANSACTION_DESCRIPTOR) {
                return false;
                }
            connection()->bro_analyzer()->ProtocolConfirmation();
            BifEvent::generate_tds_sql_batch(connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(),
                                ${sqlBatch.stream_header.header_type},
                                bytestring_to_val(${sqlBatch.query})
                                );
            }

        return true;
        %}
    };

refine typeattr TDS += &let {
    tds: bool = $context.flow.tds(this);
    };

refine typeattr TDS_RPC += &let {
    tds_rpc: bool = $context.flow.tds_rpc(this);
    };

refine typeattr TDS_SQL_BATCH += &let {
    tds_sql_batch: bool = $context.flow.tds_sql_batch(this);
    };
