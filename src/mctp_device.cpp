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

#include "mctp_device.hpp"

#include <phosphor-logging/log.hpp>

#include "libmctp-msgtypes.h"

constexpr unsigned int ctrlTxPollInterval = 5;
// Supported MCTP Version 1.3.1
struct MCTPVersionFields supportedMCTPVersion = {241, 243, 241, 0};

MCTPDevice::MCTPDevice(boost::asio::io_context& ioc,
                       std::shared_ptr<object_server>& objServer) :
    MCTPDBusInterfaces(objServer),
    io(ioc), ctrlTxTimer(ioc)
{
    initializeLogging();
    mctp = mctp_init();
    if (!mctp)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to init mctp");
        throw std::system_error(
            std::make_error_code(std::errc::not_enough_memory));
    }
}

MCTPDevice::~MCTPDevice()
{
    if (mctp)
    {
        mctp_destroy(mctp);
    }
}

void MCTPDevice::initializeLogging(void)
{
    // Default log level
    mctp_set_log_stdio(MCTP_LOG_INFO);

    if (auto envPtr = std::getenv("MCTP_TRACES"))
    {
        std::string value(envPtr);
        if (value == "1")
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "MCTP traces enabled, expect lower performance");
            mctp_set_log_stdio(MCTP_LOG_DEBUG);
            mctp_set_tracing_enabled(true);
        }
    }
}

std::optional<std::vector<uint8_t>>
    MCTPDevice::getBindingPrivateData(uint8_t /*dstEid*/)
{
    // No Binding data by default
    return std::vector<uint8_t>();
}

std::optional<std::string>
    MCTPDevice::getLocationCode(const std::vector<uint8_t>&)
{
    return std::nullopt;
}

void MCTPDevice::updateRoutingTableEntry(mctpd::RoutingTable::Entry,
                                         const std::vector<uint8_t>&)
{
    // Do nothing
}

bool MCTPDevice::sendMctpCtrlMessage(mctp_eid_t destEid,
                                     std::vector<uint8_t> req, bool tagOwner,
                                     uint8_t msgTag,
                                     std::vector<uint8_t> bindingPrivate)
{
    if (mctp_message_tx(mctp, destEid, req.data(), req.size(), tagOwner, msgTag,
                        bindingPrivate.data()) < 0)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "MCTP control: mctp_message_tx failed");
        return false;
    }
    return true;
}

static uint8_t getInstanceId(const uint8_t msg)
{
    return msg & MCTP_CTRL_HDR_INSTANCE_ID_MASK;
}

bool MCTPDevice::handleCtrlResp(void* msg, const size_t len)
{
    mctp_ctrl_msg_hdr* respHeader = reinterpret_cast<mctp_ctrl_msg_hdr*>(msg);

    auto reqItr =
        std::find_if(ctrlTxQueue.begin(), ctrlTxQueue.end(), [&](auto& ctrlTx) {
            auto& [state, retryCount, maxRespDelay, destEid, bindingPrivate,
                   req, callback] = ctrlTx;

            mctp_ctrl_msg_hdr* reqHeader =
                reinterpret_cast<mctp_ctrl_msg_hdr*>(req.data());

            if (!reqHeader)
            {
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    "MCTP Control Request Header is null");
                return false;
            }

            // TODO: Check Message terminus with Instance ID
            // (EID, TO, Msg Tag) + Instance ID
            if (getInstanceId(reqHeader->rq_dgram_inst) ==
                getInstanceId(respHeader->rq_dgram_inst))
            {
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    "Matching Control command request found");

                uint8_t* tmp = reinterpret_cast<uint8_t*>(msg);
                std::vector<uint8_t> resp =
                    std::vector<uint8_t>(tmp, tmp + len);
                state = PacketState::receivedResponse;

                // Call Callback function
                callback(state, resp);
                return true;
            }
            return false;
        });

    if (reqItr != ctrlTxQueue.end())
    {
        // Delete the entry from queue after receiving response
        ctrlTxQueue.erase(reqItr);
        return true;
    }

    phosphor::logging::log<phosphor::logging::level::WARNING>(
        "No matching Control command request found for the response");
    return false;
}

void MCTPDevice::processCtrlTxQueue()
{
    ctrlTxTimerExpired = false;
    ctrlTxTimer.expires_after(std::chrono::milliseconds(ctrlTxPollInterval));
    ctrlTxTimer.async_wait([this](const boost::system::error_code& ec) {
        if (ec == boost::asio::error::operation_aborted)
        {
            // timer aborted do nothing
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "ctrlTxTimer operation_aborted");
            return;
        }
        else if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ctrlTxTimer failed");
            return;
        }

        // Discard the packet if retry count exceeded

        ctrlTxQueue.erase(
            std::remove_if(
                ctrlTxQueue.begin(), ctrlTxQueue.end(),
                [this](auto& ctrlTx) {
                    auto& [state, retryCount, maxRespDelay, destEid,
                           bindingPrivate, req, callback] = ctrlTx;

                    maxRespDelay -= ctrlTxPollInterval;

                    // If no reponse:
                    // Retry the packet on every ctrlTxRetryDelay
                    // Total no of tries = 1 + ctrlTxRetryCount
                    if (maxRespDelay > 0 &&
                        state != PacketState::receivedResponse)
                    {
                        if (retryCount > 0 &&
                            maxRespDelay <= retryCount * ctrlTxRetryDelay)
                        {
                            if (sendMctpCtrlMessage(destEid, req, true, 0,
                                                    bindingPrivate))
                            {
                                phosphor::logging::log<
                                    phosphor::logging::level::DEBUG>(
                                    "Packet transmited");
                                state = PacketState::transmitted;
                            }

                            // Decrement retry count
                            retryCount--;
                        }

                        return false;
                    }

                    state = PacketState::noResponse;
                    std::vector<uint8_t> resp1 = {};
                    phosphor::logging::log<phosphor::logging::level::DEBUG>(
                        "Retry timed out, No response");

                    // Call Callback function
                    callback(state, resp1);
                    return true;
                }),
            ctrlTxQueue.end());

        if (ctrlTxQueue.empty())
        {
            ctrlTxTimer.cancel();
            ctrlTxTimerExpired = true;
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "ctrlTxQueue empty, canceling timer");
        }
        else
        {
            processCtrlTxQueue();
        }
    });
}

void MCTPDevice::pushToCtrlTxQueue(
    PacketState state, const mctp_eid_t destEid,
    const std::vector<uint8_t>& bindingPrivate, const std::vector<uint8_t>& req,
    std::function<void(PacketState, std::vector<uint8_t>&)>& callback)
{
    ctrlTxQueue.push_back(std::make_tuple(
        state, ctrlTxRetryCount, ((ctrlTxRetryCount + 1) * ctrlTxRetryDelay),
        destEid, bindingPrivate, req, callback));

    if (sendMctpCtrlMessage(destEid, req, true, 0, bindingPrivate))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Packet transmited");
        state = PacketState::transmitted;
    }

    if (ctrlTxTimerExpired)
    {
        processCtrlTxQueue();
    }
}

PacketState MCTPDevice::sendAndRcvMctpCtrl(
    boost::asio::yield_context& yield, const std::vector<uint8_t>& req,
    const mctp_eid_t destEid, const std::vector<uint8_t>& bindingPrivate,
    std::vector<uint8_t>& resp)
{
    if (req.empty())
    {
        return PacketState::invalidPacket;
    }

    PacketState pktState = PacketState::pushedForTransmission;
    boost::system::error_code ec;
    boost::asio::steady_timer timer(io);

    std::function<void(PacketState, std::vector<uint8_t>&)> callback =
        [&resp, &pktState, &timer](PacketState state,
                                   std::vector<uint8_t>& response) {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Callback triggered");

            resp = response;
            pktState = state;
            timer.cancel();

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("Packet state: " + std::to_string(static_cast<int>(pktState)))
                    .c_str());
        };

    pushToCtrlTxQueue(pktState, destEid, bindingPrivate, req, callback);

    // Wait for the state to change
    while (pktState == PacketState::pushedForTransmission)
    {
        timer.expires_after(std::chrono::milliseconds(ctrlTxRetryDelay));
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "sendAndRcvMctpCtrl: Timer created, ctrl cmd waiting");
        timer.async_wait(yield[ec]);
        if (ec && ec != boost::asio::error::operation_aborted)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "sendAndRcvMctpCtrl: async_wait error");
        }
    }

    return pktState;
}

mctp_server::BindingModeTypes MCTPDevice::getEndpointType(const uint8_t types)
{
    constexpr uint8_t endpointTypeMask = 0x30;
    constexpr int endpointTypeShift = 0x04;
    constexpr uint8_t simpleEndpoint = 0x00;
    constexpr uint8_t busOwnerBridge = 0x01;

    uint8_t endpointType = (types & endpointTypeMask) >> endpointTypeShift;

    if (endpointType == simpleEndpoint)
    {
        return mctp_server::BindingModeTypes::Endpoint;
    }
    else if (endpointType == busOwnerBridge)
    {
        // TODO: need to differentiate between BusOwner and Bridge
        return mctp_server::BindingModeTypes::Bridge;
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid endpoint type value");
        throw;
    }
}

MsgTypes MCTPDevice::getMsgTypes(const std::vector<uint8_t>& msgType)
{
    MsgTypes messageTypes;

    for (auto type : msgType)
    {
        switch (type)
        {
            case MCTP_MESSAGE_TYPE_MCTP_CTRL: {
                messageTypes.mctpControl = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_PLDM: {
                messageTypes.pldm = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_NCSI: {
                messageTypes.ncsi = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_ETHERNET: {
                messageTypes.ethernet = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_NVME: {
                messageTypes.nvmeMgmtMsg = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_SPDM: {
                messageTypes.spdm = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_VDPCI: {
                messageTypes.vdpci = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_VDIANA: {
                messageTypes.vdiana = true;
                break;
            }
            default: {
                // TODO: Add OEM Message Type support
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Invalid message type");
                break;
            }
        }
    }
    return messageTypes;
}

std::optional<mctp_eid_t> MCTPDevice::getEIDFromUUID(const std::string& uuidStr)
{
    for (const auto& [eid, deviceUUID] : uuidTable)
    {
        if (uuidStr.compare(deviceUUID) == 0)
        {
            return eid;
        }
    }
    return std::nullopt;
}

bool MCTPDevice::isEIDMappedToUUID(const mctp_eid_t eid,
                                   const std::string& destUUID)
{
    std::optional<mctp_eid_t> eidFromTable = getEIDFromUUID(destUUID);
    if (eidFromTable.has_value())
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("EID from table " + std::to_string(eidFromTable.value())).c_str());
        if (eid == eidFromTable.value())
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("Endpoint already Registered with EID " + std::to_string(eid))
                    .c_str());
            return true;
        }
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("Endpoint needs re-registration. EID from device:" +
             std::to_string(eid) +
             " EID from table:" + std::to_string(eidFromTable.value()))
                .c_str());
    }
    return false;
}

std::optional<mctp_eid_t>
    MCTPDevice::getEIDForReregistration(const std::string& destUUID)
{
    if (auto eidFromTable = getEIDFromUUID(destUUID))
    {
        unregisterEndpoint(eidFromTable.value());
        // Give priority for EID from UUID table while re-registering
        return eidFromTable.value();
    }
    return std::nullopt;
}

bool MCTPDevice::isMCTPVersionSupported(const MCTPVersionFields& version)
{
    if ((version.major == supportedMCTPVersion.major) &&
        (version.minor == supportedMCTPVersion.minor) &&
        (version.update == supportedMCTPVersion.update))
    {
        return true;
    }
    return false;
}

bool MCTPDevice::isEIDRegistered(mctp_eid_t eid)
{
    if (endpointInterface.count(eid) > 0)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("Endpoint already Registered with EID " + std::to_string(eid))
                .c_str());
        return true;
    }

    return false;
}

void MCTPDevice::unregisterEndpoint(mctp_eid_t eid)
{
    bool epIntf = removeInterface(eid, endpointInterface);
    bool msgTypeIntf = removeInterface(eid, msgTypeInterface);
    bool uuidIntf = removeInterface(eid, uuidInterface);
    // Vendor ID interface is optional thus not considering return status
    removeInterface(eid, vendorIdInterface);
    removeInterface(eid, locationCodeInterface);
    removeInterface(eid, deviceInterface);

    if (epIntf && msgTypeIntf && uuidIntf)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("Device Unregistered: EID = " + std::to_string(eid)).c_str());
    }
    routingTable.removeEntry(eid);
}
