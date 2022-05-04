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

#include "mctp_endpoint.hpp"

#include "mctp_cmd_encoder.hpp"

#include <phosphor-logging/log.hpp>

#include "libmctp-msgtypes.h"

using RoutingTableEntry = mctpd::RoutingTable::Entry;

MCTPEndpoint::MCTPEndpoint(boost::asio::io_context& ioc,
                           std::shared_ptr<object_server>& objServer) :
    MCTPDevice(ioc, objServer)
{
}

bool MCTPEndpoint::isReceivedPrivateDataCorrect(const void* /*bindingPrivate*/)
{
    return true;
}

void MCTPEndpoint::handleCtrlReq(uint8_t destEid, void* bindingPrivate,
                                 const void* req, size_t len, uint8_t msgTag)
{
    if (req == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "MCTP Control Request is not initialized.");
        return;
    }
    if (!isReceivedPrivateDataCorrect(bindingPrivate))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Binding Private Data is not correct.");
        return;
    }

    std::vector<uint8_t> response = {};
    bool sendResponse = false;
    auto reqPtr = reinterpret_cast<const uint8_t*>(req);
    std::vector<uint8_t> request(reqPtr, reqPtr + len);
    mctp_ctrl_msg_hdr* reqHeader =
        reinterpret_cast<mctp_ctrl_msg_hdr*>(request.data());

    if (!reqHeader)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "MCTP Control Request Header is null");
        return;
    }

    switch (reqHeader->command_code)
    {
        case MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY: {
            sendResponse = handlePrepareForEndpointDiscovery(
                destEid, bindingPrivate, request, response);
            break;
        }
        case MCTP_CTRL_CMD_ENDPOINT_DISCOVERY: {
            sendResponse = handleEndpointDiscovery(destEid, bindingPrivate,
                                                   request, response);
            break;
        }
        case MCTP_CTRL_CMD_GET_ENDPOINT_ID: {
            sendResponse =
                handleGetEndpointId(destEid, bindingPrivate, request, response);
            break;
        }
        case MCTP_CTRL_CMD_SET_ENDPOINT_ID: {
            sendResponse =
                handleSetEndpointId(destEid, bindingPrivate, request, response);
            break;
        }
        case MCTP_CTRL_CMD_GET_VERSION_SUPPORT: {
            sendResponse = handleGetVersionSupport(destEid, bindingPrivate,
                                                   request, response);
            break;
        }
        case MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT: {
            sendResponse = handleGetMsgTypeSupport(destEid, bindingPrivate,
                                                   request, response);
            break;
        }
        case MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT: {
            sendResponse =
                handleGetVdmSupport(destEid, bindingPrivate, request, response);
            break;
        }
        case MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES: {
            sendResponse = handleGetRoutingTable(request, response);
            break;
        }
        default: {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Message not supported");
        }
    }

    if (sendResponse)
    {
        auto respHeader = reinterpret_cast<mctp_ctrl_msg_hdr*>(response.data());
        *respHeader = *reqHeader;
        respHeader->rq_dgram_inst &=
            static_cast<uint8_t>(~MCTP_CTRL_HDR_FLAG_REQUEST);
        mctp_message_tx(mctp, destEid, response.data(), response.size(), false,
                        msgTag, bindingPrivate);
    }
    return;
}

bool MCTPEndpoint::handlePrepareForEndpointDiscovery(mctp_eid_t, void*,
                                                     std::vector<uint8_t>&,
                                                     std::vector<uint8_t>&)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Message not supported");
    return false;
}

bool MCTPEndpoint::handleEndpointDiscovery(mctp_eid_t, void*,
                                           std::vector<uint8_t>&,
                                           std::vector<uint8_t>&)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Message not supported");
    return false;
}

bool MCTPEndpoint::handleGetEndpointId(mctp_eid_t destEid, void*,
                                       std::vector<uint8_t>&,
                                       std::vector<uint8_t>& response)
{
    response.resize(sizeof(mctp_ctrl_resp_get_eid));
    auto resp = reinterpret_cast<mctp_ctrl_resp_get_eid*>(response.data());

    bool busownerMode =
        bindingModeType == mctp_server::BindingModeTypes::BusOwner ? true
                                                                   : false;
    mctp_ctrl_cmd_get_endpoint_id(mctp, destEid, busownerMode, resp);
    return true;
}

bool MCTPEndpoint::handleSetEndpointId(mctp_eid_t destEid, void*,
                                       std::vector<uint8_t>& request,
                                       std::vector<uint8_t>& response)
{
    if (bindingModeType != mctp_server::BindingModeTypes::Endpoint)
    {
        return false;
    }
    response.resize(sizeof(mctp_ctrl_resp_set_eid));
    auto resp = reinterpret_cast<mctp_ctrl_resp_set_eid*>(response.data());
    auto req = reinterpret_cast<mctp_ctrl_cmd_set_eid*>(request.data());

    mctp_ctrl_cmd_set_endpoint_id(mctp, destEid, req, resp);
    if (resp->completion_code == MCTP_CTRL_CC_SUCCESS)
    {
        busOwnerEid = destEid;
        ownEid = resp->eid_set;
    }
    return true;
}

bool MCTPEndpoint::handleGetVersionSupport(mctp_eid_t, void*,
                                           std::vector<uint8_t>& request,
                                           std::vector<uint8_t>& response)
{
    response.resize(sizeof(mctp_ctrl_resp_get_mctp_ver_support));
    auto req =
        reinterpret_cast<mctp_ctrl_cmd_get_mctp_ver_support*>(request.data());
    auto resp =
        reinterpret_cast<mctp_ctrl_resp_get_mctp_ver_support*>(response.data());

    std::vector<version_entry> versions = {};

    if (versionNumbersForUpperLayerResponder.find(req->msg_type_number) ==
        versionNumbersForUpperLayerResponder.end())
    {
        resp->completion_code =
            MCTP_CTRL_CC_GET_MCTP_VER_SUPPORT_UNSUPPORTED_TYPE;
    }
    else
    {
        versions.push_back(
            versionNumbersForUpperLayerResponder.at(req->msg_type_number));
        resp->completion_code = MCTP_CTRL_CC_SUCCESS;
    }
    resp->number_of_entries = static_cast<uint8_t>(versions.size());
    std::copy(reinterpret_cast<uint8_t*>(versions.data()),
              reinterpret_cast<uint8_t*>(versions.data() + versions.size()),
              std::back_inserter(response));
    return true;
}

std::vector<uint8_t> MCTPEndpoint::getBindingMsgTypes()
{
    // TODO: endpoints should expose info about message types
    // supported by upper layer applications
    std::vector<uint8_t> bindingMsgTypes = {MCTP_MESSAGE_TYPE_MCTP_CTRL};
    return bindingMsgTypes;
}

bool MCTPEndpoint::handleGetMsgTypeSupport(mctp_eid_t, void*,
                                           std::vector<uint8_t>&,
                                           std::vector<uint8_t>& response)
{
    response.resize(sizeof(mctp_ctrl_resp_get_msg_type_support));
    std::vector<uint8_t> supportedMsgTypes = getBindingMsgTypes();
    auto resp =
        reinterpret_cast<mctp_ctrl_resp_get_msg_type_support*>(response.data());
    resp->completion_code = MCTP_CTRL_CC_SUCCESS;
    resp->msg_type_count = static_cast<uint8_t>(supportedMsgTypes.size());
    std::copy(supportedMsgTypes.begin(), supportedMsgTypes.end(),
              std::back_inserter(response));
    return true;
}

bool MCTPEndpoint::handleGetVdmSupport(
    [[maybe_unused]] mctp_eid_t destEid, [[maybe_unused]] void* bindingPrivate,
    [[maybe_unused]] std::vector<uint8_t>& request,
    [[maybe_unused]] std::vector<uint8_t>& response)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Message not supported");
    return false;
}

bool MCTPEndpoint::handleGetRoutingTable(const std::vector<uint8_t>& request,
                                         std::vector<uint8_t>& response)
{
    static constexpr size_t errRespSize = 3;
    if (bindingModeType == mctp_server::BindingModeTypes::Endpoint)
    {
        // Command is not supported for endpoints. No response will be sent
        return false;
    }
    auto getRoutingTableRequest =
        reinterpret_cast<const mctp_ctrl_cmd_get_routing_table*>(
            request.data());
    auto dest =
        reinterpret_cast<mctp_ctrl_resp_get_routing_table*>(response.data());
    if (getRoutingTableRequest->entry_handle != 0x00)
    {
        response.resize(errRespSize);
        dest->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
        dest->number_of_entries = 0;
        // Return true so that a response will be sent with error code
        return true;
    }

    bool status = false;
    auto& entries = this->routingTable.getAllEntries();
    std::vector<RoutingTableEntry::MCTPLibData> entriesLibFormat;
    // TODO. Combine EIDs in a range.
    for (const auto& [eid, data] : entries)
    {
        entriesLibFormat.emplace_back(data.routeEntry);
    }

    size_t estSize =
        sizeof(mctp_ctrl_resp_get_routing_table) +
        entries.size() * sizeof(get_routing_table_entry_with_address);
    response.resize(estSize);
    size_t formattedRespSize = 0;
    dest = reinterpret_cast<mctp_ctrl_resp_get_routing_table*>(response.data());
    // TODO. Split if entries > 255
    if (!mctp_encode_ctrl_cmd_rsp_get_routing_table(
            dest, entriesLibFormat.data(),
            static_cast<uint8_t>(entriesLibFormat.size()), &formattedRespSize))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error formatting get routing table");
        formattedRespSize = 0;
    }
    response.resize(formattedRespSize);
    status = true;
    return status;
}

bool MCTPEndpoint::discoveryNotifyCtrlCmd(
    boost::asio::yield_context& yield,
    const std::vector<uint8_t>& bindingPrivate, const mctp_eid_t destEid)
{
    std::vector<uint8_t> req = {};
    std::vector<uint8_t> resp = {};

    if (!getFormattedReq<MCTP_CTRL_CMD_DISCOVERY_NOTIFY>(req))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Discovery Notify: Request formatting failed");
        return false;
    }

    if (PacketState::receivedResponse !=
        sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Discovery Notify: Unable to get response");
        return false;
    }

    if (!checkRespSizeAndCompletionCode<mctp_ctrl_resp_discovery_notify>(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Discovery Notify failed");
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Discovery Notify success");
    return true;
}