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

#include "mctp_dbus_interfaces.hpp"
#include "routing_table.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

enum class PacketState : uint8_t
{
    invalidPacket,
    pushedForTransmission,
    transmitted,
    receivedResponse,
    noResponse
};

struct MCTPVersionFields
{
    uint8_t major;
    uint8_t minor;
    uint8_t update;
    uint8_t alpha;
};

struct MctpVersionSupportCtrlResp
{
    mctp_ctrl_msg_hdr ctrlMsgHeader;
    uint8_t completionCode;
    uint8_t verNoEntryCount;
    std::vector<struct MCTPVersionFields> verNoEntry;
};

class MCTPDevice : public MCTPDBusInterfaces
{
  public:
    MCTPDevice(boost::asio::io_context& ioc,
               std::shared_ptr<object_server>& objServer);
    MCTPDevice() = delete;
    ~MCTPDevice();

  protected:
    uint8_t busOwnerEid;
    uint8_t ownEid;
    uint8_t ctrlTxRetryCount;
    unsigned int ctrlTxRetryDelay;
    mctp_server::BindingModeTypes bindingModeType{};
    mctp_server::MctpPhysicalMediumIdentifiers bindingMediumID{};
    mctpd::RoutingTable routingTable;
    boost::asio::io_context& io;
    std::unordered_map<uint8_t, version_entry>
        versionNumbersForUpperLayerResponder;
    // <eid, uuid>
    std::unordered_map<mctp_eid_t, std::string> uuidTable;
    struct mctp* mctp = nullptr;

    virtual std::optional<std::string>
        getLocationCode(const std::vector<uint8_t>& bindingPrivate);
    virtual void
        updateRoutingTableEntry(mctpd::RoutingTable::Entry entry,
                                const std::vector<uint8_t>& privateData);
    virtual std::optional<std::vector<uint8_t>>
        getBindingPrivateData(uint8_t dstEid);

    PacketState sendAndRcvMctpCtrl(boost::asio::yield_context& yield,
                                   const std::vector<uint8_t>& req,
                                   const mctp_eid_t destEid,
                                   const std::vector<uint8_t>& bindingPrivate,
                                   std::vector<uint8_t>& resp);
    bool handleCtrlResp(void* msg, const size_t len);
    bool isEIDRegistered(mctp_eid_t eid);
    bool isEIDMappedToUUID(const mctp_eid_t eid, const std::string& destUUID);
    std::optional<mctp_eid_t> getEIDFromUUID(const std::string& uuidStr);
    void unregisterEndpoint(mctp_eid_t eid);
    std::optional<mctp_eid_t>
        getEIDForReregistration(const std::string& destUUID);
    mctp_server::BindingModeTypes getEndpointType(const uint8_t types);
    MsgTypes getMsgTypes(const std::vector<uint8_t>& msgType);
    bool isMCTPVersionSupported(const MCTPVersionFields& version);

  private:
    bool ctrlTxTimerExpired = true;
    boost::asio::steady_timer ctrlTxTimer;
    // <state, retryCount, maxRespDelay, destEid, BindingPrivate, ReqPacket,
    //  Callback>
    std::vector<
        std::tuple<PacketState, uint8_t, unsigned int, mctp_eid_t,
                   std::vector<uint8_t>, std::vector<uint8_t>,
                   std::function<void(PacketState, std::vector<uint8_t>&)>>>
        ctrlTxQueue;

    void initializeLogging();
    void processCtrlTxQueue();
    bool sendMctpCtrlMessage(mctp_eid_t destEid, std::vector<uint8_t> req,
                             bool tagOwner, uint8_t msgTag,
                             std::vector<uint8_t> bindingPrivate);
    void pushToCtrlTxQueue(
        PacketState pktState, const mctp_eid_t destEid,
        const std::vector<uint8_t>& bindingPrivate,
        const std::vector<uint8_t>& req,
        std::function<void(PacketState, std::vector<uint8_t>&)>& callback);
};