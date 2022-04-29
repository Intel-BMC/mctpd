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

#include <functional>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus/match.hpp>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

using mctp_eid_t = uint8_t;

namespace bridging
{
class MCTPServiceScanner
{
  public:
    // TODO. Add endpoint type in callback. Currently no way to identify from
    // DBus
    struct MCTPService
    {
        std::string name;
        std::string bindingID{};
        std::string bindingMediumID{};
        std::string bindingMode{};
    };
    struct EndPoint
    {
        mctp_eid_t eid;
        std::string endpointType;
        MCTPService service;
    };
    using Callback = std::function<void(EndPoint, bool)>;
    using EidRemovedCallback = std::function<void(EndPoint)>;
    MCTPServiceScanner(std::shared_ptr<sdbusplus::asio::connection>& conn);
    inline void setCallback(Callback handler)
    {
        onNewEid = std::move(handler);
    }
    inline void setEidRemovedCallback(EidRemovedCallback handler)
    {
        onEidRemovedHandler = std::move(handler);
    }
    template <typename It>
    inline void setAllowedBuses(It begin, It end)
    {
        allowedDestBuses.insert(begin, end);
    }
    void scan();

  private:
    void onHotPluggedEid(sdbusplus::message::message& message);
    void onEidRemoved(sdbusplus::message::message& message);
    const MCTPService& getMctpServiceDetails(boost::asio::yield_context yield,
                                             const std::string& serviceName);
    void scanForEIDs(const std::string& serviceName,
                     boost::asio::yield_context yield);

    std::vector<std::string> getMCTPServices(boost::asio::yield_context yield);
    bool isAllowedBus(const std::string& bus, boost::asio::yield_context yield);
    Callback onNewEid;
    EidRemovedCallback onEidRemovedHandler;
    std::shared_ptr<sdbusplus::asio::connection> connection;
    std::vector<sdbusplus::bus::match::match> signalMatches;
    std::unordered_map<std::string, MCTPService> cachedServices;
    std::unordered_set<std::string> allowedDestBuses;
    std::unordered_set<std::string> disallowedDestBuses;
};
} // namespace bridging