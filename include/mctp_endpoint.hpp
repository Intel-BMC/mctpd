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

#include "mctp_device.hpp"

class MCTPEndpoint : public MCTPDevice
{
  public:
    MCTPEndpoint(boost::asio::io_context& ioc,
                 std::shared_ptr<object_server>& objServer);
    MCTPEndpoint() = delete;
    virtual ~MCTPEndpoint() = default;

  protected:
    virtual bool isReceivedPrivateDataCorrect(const void* bindingPrivate);
    virtual bool handleEndpointDiscovery(mctp_eid_t destEid,
                                         void* bindingPrivate,
                                         std::vector<uint8_t>& request,
                                         std::vector<uint8_t>& response);
    virtual bool handleSetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                     std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response);
    virtual bool handleGetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                     std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response);
    virtual bool handleGetVersionSupport(mctp_eid_t destEid,
                                         void* bindingPrivate,
                                         std::vector<uint8_t>& request,
                                         std::vector<uint8_t>& response);
    virtual bool handleGetMsgTypeSupport(mctp_eid_t destEid,
                                         void* bindingPrivate,
                                         std::vector<uint8_t>& request,
                                         std::vector<uint8_t>& response);
    virtual bool handleGetVdmSupport(mctp_eid_t endpointEid,
                                     void* bindingPrivate,
                                     std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response);
    virtual bool handleGetRoutingTable(const std::vector<uint8_t>& request,
                                       std::vector<uint8_t>& response);
    virtual bool handlePrepareForEndpointDiscovery(
        mctp_eid_t destEid, void* bindingPrivate, std::vector<uint8_t>& request,
        std::vector<uint8_t>& response);

    bool discoveryNotifyCtrlCmd(boost::asio::yield_context& yield,
                                const std::vector<uint8_t>& bindingPrivate,
                                const mctp_eid_t destEid);
    std::vector<uint8_t> getBindingMsgTypes();
    void handleCtrlReq(uint8_t destEid, void* bindingPrivate, const void* req,
                       size_t len, uint8_t msgTag);
};