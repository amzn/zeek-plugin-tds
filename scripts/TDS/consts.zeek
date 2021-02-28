## Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: BSD-3-Clause

module TDS;

export {
    ## TDS default commands
    const commands = {
        [0x00] = "NOP",
        [0x01] = "SQL Batch",
        [0x02] = "Pre TDS7 Login",
        [0x03] = "Remote Procedure Call",
        [0x04] = "SQL Batch Server Response",
        [0x05] = "Unused",
        [0x06] = "Attention Request",
        [0x07] = "Bulk Load Data",
        [0x0E] = "Transcation Manager Request",
        [0x0F] = "TDS5 Query",
        [0x10] = "TDS7 Login",
        [0x11] = "SSPI Message",
        [0x12] = "Pre-Login Request",
        } &default=function(i: count):string { return fmt("command (%d)", i); } &redef;

    ## TDS header types
    const header_types = {
        [0x0000] = "NOP",
        [0x0001] = "Query notifications",
        [0x0002] = "Transaction Descriptor",
        } &default=function(i: count):string { return fmt("command (%d)", i); } &redef;
    }
