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

#include <phosphor-logging/log.hpp>

#pragma once

template <typename Handler>
inline auto registerSignalHandler(sdbusplus::bus::bus& bus, Handler handler,
                                  const std::string& interface,
                                  const std::string& member,
                                  const std::string& pathNamespace)
{
    std::string matcherString = sdbusplus::bus::match::rules::type::signal();

    matcherString += sdbusplus::bus::match::rules::interface(interface);
    matcherString += sdbusplus::bus::match::rules::member(member);
    matcherString +=
        sdbusplus::bus::match::rules::path_namespace(pathNamespace);

    return sdbusplus::bus::match::match(bus, matcherString.c_str(), handler);
}

template <typename Property>
inline Property
    readPropertyValue(boost::asio::yield_context yield,
                      sdbusplus::asio::connection& bus,
                      const std::string& service, const std::string& path,
                      const std::string& interface, const std::string& property)
{
    boost::system::error_code ec;
    using RetType = std::variant<Property>;
    RetType value;
    value = bus.yield_method_call<RetType>(yield, ec, service, path,
                                           "org.freedesktop.DBus.Properties",
                                           "Get", interface, property);

    if (ec)
    {
        throw std::runtime_error("Error reading property " + property + "." +
                                 ec.message());
    }
    return std::get<Property>(value);
}

template <typename... Args>
inline void logLine(Args... args)
{
    std::stringstream ss;
    (ss << ... << args);
    phosphor::logging::log<phosphor::logging::level::INFO>(ss.str().c_str());
}

template <typename Arr>
inline std::string arrToString(Arr&& arr)
{
    std::stringstream ss;
    for (int n : arr)
    {
        ss << n << ' ';
    }
    return ss.str();
}
