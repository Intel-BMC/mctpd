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

#include "mctp_endpoint.hpp"
#include "utils/device_watcher.hpp"
#include "utils/eid_pool.hpp"

struct MsgTypeSupportCtrlResp
{
    mctp_ctrl_msg_hdr ctrlMsgHeader;
    uint8_t completionCode;
    uint8_t msgTypeCount;
    std::vector<uint8_t> msgType;
};

// VendorPCI ID Support Structure
struct MctpVendIdMsgSupportResp
{
    mctp_ctrl_msg_hdr ctrlMsgHeader;
    uint8_t completionCode;
    uint8_t vendorIdSet;
    uint8_t vendorIdFormat;
    uint16_t vendorIdFormatData;
    uint16_t vendorIdSetCmdType;
};

// Bridge is both BusOwner and Endpoint
class MCTPBridge : public MCTPEndpoint
{
  public:
    MCTPBridge(boost::asio::io_context& ioc,
               std::shared_ptr<object_server>& objServer);
    MCTPBridge() = delete;
    ~MCTPBridge() = default;

  protected:
    mctpd::EidPool eidPool;
    mctpd::DeviceWatcher deviceWatcher{};

    bool getEidCtrlCmd(boost::asio::yield_context& yield,
                       const std::vector<uint8_t>& bindingPrivate,
                       const mctp_eid_t destEid, std::vector<uint8_t>& resp);
    bool setEidCtrlCmd(boost::asio::yield_context& yield,
                       const std::vector<uint8_t>& bindingPrivate,
                       const mctp_eid_t destEid,
                       const mctp_ctrl_cmd_set_eid_op operation, mctp_eid_t eid,
                       std::vector<uint8_t>& resp);
    bool getUuidCtrlCmd(boost::asio::yield_context& yield,
                        const std::vector<uint8_t>& bindingPrivate,
                        const mctp_eid_t destEid, std::vector<uint8_t>& resp);
    bool getMsgTypeSupportCtrlCmd(boost::asio::yield_context& yield,
                                  const std::vector<uint8_t>& bindingPrivate,
                                  const mctp_eid_t destEid,
                                  MsgTypeSupportCtrlResp* msgTypeSupportResp);
    bool getMctpVersionSupportCtrlCmd(
        boost::asio::yield_context& yield,
        const std::vector<uint8_t>& bindingPrivate, const mctp_eid_t destEid,
        uint8_t msgTypeNo,
        MctpVersionSupportCtrlResp* mctpVersionSupportCtrlResp);
    void
        getVendorDefinedMessageTypes(boost::asio::yield_context yield,
                                     const std::vector<uint8_t>& bindingPrivate,
                                     mctp_eid_t destEid,
                                     EndpointProperties& epProperties);
    // vendor PCI ID Function
    bool getPCIVDMessageSupportCtrlCmd(
        boost::asio::yield_context& yield,
        const std::vector<uint8_t>& bindingPrivate, const mctp_eid_t destEid,
        std::vector<uint16_t>& vendorSetIdList, std::string& venformat);
    bool getRoutingTableCtrlCmd(boost::asio::yield_context& yield,
                                const std::vector<uint8_t>& bindingPrivate,
                                const mctp_eid_t destEid, uint8_t entryHandle,
                                std::vector<uint8_t>& resp);
    //   private:
    std::optional<mctp_eid_t>
        busOwnerRegisterEndpoint(boost::asio::yield_context& yield,
                                 const std::vector<uint8_t>& bindingPrivate,
                                 mctp_eid_t eid);
    void sendRoutingTableEntriesToBridge(
        const mctp_eid_t bridge, const std::vector<uint8_t>& bindingPrivate);
    void sendNewRoutingTableEntryToAllBridges(
        const mctpd::RoutingTable::Entry& entry);

  private:
    void logUnsupportedMCTPVersion(
        const std::vector<struct MCTPVersionFields> versionsData,
        const mctp_eid_t eid);
    void sendRoutingTableEntries(
        const std::vector<mctpd::RoutingTable::Entry::MCTPLibData>& entries,
        std::optional<std::vector<uint8_t>> bindingPrivateData,
        const mctp_eid_t eid = 0);
};