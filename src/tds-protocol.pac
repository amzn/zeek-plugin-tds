## Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: BSD-3-Clause

#
# Binpac for Microsoft TDS analyser.
# More information from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/b46a581a-39de-4745-b076-ec4dbb7d13ec
#

##############################
#         CONSTANTS          #
##############################

enum cmd_codes {
    SQL_BATCH               = 0x01,
    PRE_TDS7_LOGIN          = 0x02,
    REMOTE_PROCEDURE_CALL   = 0x03,
    RESPONSE                = 0x04,
    UNUSED                  = 0x05,
    ATTENTION_REQUEST       = 0x06,
    BULK_LOAD_DATA          = 0x07,
    TRANSACTION_MANAGER     = 0x0e,
    TDS5_QUERY              = 0x0F,
    TDS7_LOGIN              = 0x10,
    SSPI_MESSAGE            = 0x11,
    TDS7_PRELOGIN           = 0x12
    };

##############################
##        RECORD TYPES       #
##############################

## All multiple byte fields are set in little endian order
## Packets are set in big endian order

type TDS_PDU(is_orig: bool) = case is_orig of {
    true  -> request    : TDS_Request;
    false -> response   : TDS_Response;
    } &byteorder=bigendian;

# switch for the request portion
type TDS_Request = record {
    header: TDS;
    data: case(header.command) of {
        REMOTE_PROCEDURE_CALL   -> remoteProcedureCall  : TDS_RPC;
        SQL_BATCH               -> sqlBatch             : TDS_SQL_BATCH;
        default                 -> unknown              : bytestring &restofdata;
        };
    } &byteorder=bigendian;

# switch for the response portion
type TDS_Response = record {
    header: TDS;
    data: case(header.command) of {
        RESPONSE        -> response : TDS_RESPONSE;
        ##! SQL_BATCH   -> sqlBatch : TDS_SQL_BATCH;
        default         -> unknown  : bytestring &restofdata;
        };
    } &byteorder=bigendian;

type TDS = record {
    command         : uint8;
    status          : uint8;
    len             : uint16;
    channel         : uint16;
    packet_number   : uint8;
    window          : uint8;
    } &byteorder=bigendian;

type TDS_RPC = record {
    stream_header   : Stream_Header;
    name_len        : uint16 &byteorder=littleendian;
    procedure_name  : bytestring &length=name_len*2;
    option_flags    : uint16 &byteorder=littleendian;
    parameters      : bytestring &restofdata;
    } &byteorder=bigendian;
    
type TDS_SQL_BATCH = record {
    stream_header   : Stream_Header;
    query           : bytestring &restofdata;
    } &byteorder=bigendian;

type Stream_Header = record {
    total_len       : uint32;
    header_len      : uint32;
    header_type     : uint16;
    descriptor      : uint64;
    request_count   : uint32;
    } &byteorder=littleendian;

type TDS_RESPONSE = record {
    tokens  : bytestring &restofdata;
    } &byteorder=bigendian;
