/*
// Copyright (c) 2022 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#pragma once

#include <phosphor-logging/log.hpp>

#include "libmctp-cmds.h"

constexpr size_t minCmdRespSize = 4;

static uint8_t createInstanceId()
{
    static uint8_t instanceId = 0x00;

    instanceId = (instanceId + 1) & MCTP_CTRL_HDR_INSTANCE_ID_MASK;
    return instanceId;
}

static uint8_t getRqDgramInst()
{
    uint8_t instanceID = createInstanceId();
    uint8_t rqDgramInst = instanceID | MCTP_CTRL_HDR_FLAG_REQUEST;
    return rqDgramInst;
}

template <int cmd, typename... Args>
bool getFormattedReq(std::vector<uint8_t>& req, Args&&... reqParam)
{
    if constexpr (cmd == MCTP_CTRL_CMD_GET_ENDPOINT_ID)
    {
        req.resize(sizeof(mctp_ctrl_cmd_get_eid));
        mctp_ctrl_cmd_get_eid* getEidCmd =
            reinterpret_cast<mctp_ctrl_cmd_get_eid*>(req.data());

        mctp_encode_ctrl_cmd_get_eid(getEidCmd, getRqDgramInst());
        return true;
    }
    else if constexpr (cmd == MCTP_CTRL_CMD_SET_ENDPOINT_ID)
    {
        req.resize(sizeof(mctp_ctrl_cmd_set_eid));
        mctp_ctrl_cmd_set_eid* setEidCmd =
            reinterpret_cast<mctp_ctrl_cmd_set_eid*>(req.data());

        mctp_encode_ctrl_cmd_set_eid(setEidCmd, getRqDgramInst(),
                                     std::forward<Args>(reqParam)...);
        return true;
    }
    else if constexpr (cmd == MCTP_CTRL_CMD_GET_ENDPOINT_UUID)
    {
        req.resize(sizeof(mctp_ctrl_cmd_get_uuid));
        mctp_ctrl_cmd_get_uuid* getUuid =
            reinterpret_cast<mctp_ctrl_cmd_get_uuid*>(req.data());

        mctp_encode_ctrl_cmd_get_uuid(getUuid, getRqDgramInst());
        return true;
    }
    else if constexpr (cmd == MCTP_CTRL_CMD_GET_VERSION_SUPPORT)
    {
        req.resize(sizeof(mctp_ctrl_cmd_get_mctp_ver_support));
        mctp_ctrl_cmd_get_mctp_ver_support* getVerSupport =
            reinterpret_cast<mctp_ctrl_cmd_get_mctp_ver_support*>(req.data());

        mctp_encode_ctrl_cmd_get_ver_support(getVerSupport, getRqDgramInst(),
                                             std::forward<Args>(reqParam)...);
        return true;
    }

    else if constexpr (cmd == MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT)
    {
        req.resize(sizeof(mctp_ctrl_cmd_get_msg_type_support));
        mctp_ctrl_cmd_get_msg_type_support* getMsgType =
            reinterpret_cast<mctp_ctrl_cmd_get_msg_type_support*>(req.data());

        mctp_encode_ctrl_cmd_get_msg_type_support(getMsgType, getRqDgramInst());
        return true;
    }
    else if constexpr (cmd == MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT)
    {
        req.resize(sizeof(struct mctp_ctrl_cmd_get_vdm_support));
        struct mctp_ctrl_cmd_get_vdm_support* getVdmSupport =
            reinterpret_cast<struct mctp_ctrl_cmd_get_vdm_support*>(req.data());

        mctp_encode_ctrl_cmd_get_vdm_support(getVdmSupport, getRqDgramInst(),
                                             std::forward<Args>(reqParam)...);
        return true;
    }
    else if constexpr (cmd == MCTP_CTRL_CMD_DISCOVERY_NOTIFY)
    {
        req.resize(sizeof(mctp_ctrl_cmd_discovery_notify));
        mctp_ctrl_cmd_discovery_notify* discoveryNotify =
            reinterpret_cast<mctp_ctrl_cmd_discovery_notify*>(req.data());

        mctp_encode_ctrl_cmd_discovery_notify(discoveryNotify,
                                              getRqDgramInst());
        return true;
    }
    else if constexpr (cmd == MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES)
    {
        req.resize(sizeof(mctp_ctrl_cmd_get_routing_table));
        mctp_ctrl_cmd_get_routing_table* getRoutingTable =
            reinterpret_cast<mctp_ctrl_cmd_get_routing_table*>(req.data());

        mctp_encode_ctrl_cmd_get_routing_table(
            getRoutingTable, getRqDgramInst(), std::forward<Args>(reqParam)...);
        return true;
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Control command not defined");
        return false;
    }
}

static bool checkMinRespSize(const std::vector<uint8_t>& resp)
{
    return (resp.size() >= minCmdRespSize);
}

template <typename structure>
static bool checkRespSizeAndCompletionCode(std::vector<uint8_t>& resp)
{
    if (!checkMinRespSize(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid response length");
        return false;
    }

    structure* respPtr = reinterpret_cast<structure*>(resp.data());

    if (respPtr->completion_code != MCTP_CTRL_CC_SUCCESS ||
        resp.size() != sizeof(structure))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid response", phosphor::logging::entry("LEN=%d", resp.size()),
            phosphor::logging::entry("CC=0x%02X", respPtr->completion_code));
        return false;
    }
    return true;
}