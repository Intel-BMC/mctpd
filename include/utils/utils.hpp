#pragma once
#include <boost/algorithm/string/predicate.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/container/flat_map.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus/match.hpp>
static std::unique_ptr<sdbusplus::bus::match::match> powerMatch = nullptr;

namespace power
{
const static constexpr char* interface = "xyz.openbmc_project.State.Host";
const static constexpr char* path = "/xyz/openbmc_project/state/host0";
const static constexpr char* property = "CurrentHostState";
} // namespace power

namespace properties
{
constexpr const char* interface = "org.freedesktop.DBus.Properties";
} // namespace properties

template <class T>
void setupPowerMatch(std::shared_ptr<sdbusplus::asio::connection> conn,
                     const T& bindingPtr)
{
    if (powerMatch || bindingPtr == nullptr || conn == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unable to setup power match");
        return;
    }

    static boost::asio::steady_timer timer(conn->get_io_context());
    std::string matchString =
        sdbusplus::bus::match::rules::type::signal() +
        sdbusplus::bus::match::rules::interface(properties::interface) +
        sdbusplus::bus::match::rules::path(power::path) +
        sdbusplus::bus::match::rules::argN(0, power::interface);

    powerMatch = std::make_unique<sdbusplus::bus::match::match>(
        static_cast<sdbusplus::bus::bus&>(*conn), matchString,
        [bindingPtr](sdbusplus::message::message& message) {
            std::string objectName;
            boost::container::flat_map<std::string, std::variant<std::string>>
                values;
            message.read(objectName, values);
            auto findState = values.find(power::property);
            if (findState == values.end())
            {
                return;
            }

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Host State changed. Triggering device discovery");

            bool on = boost::ends_with(std::get<std::string>(findState->second),
                                       ".Running");

            // on and off comes too quickly
            int delayInSec = 3;
            if (on)
            {
                delayInSec = 10;
            }
            timer.expires_after(std::chrono::seconds(delayInSec));
            timer.async_wait([&](boost::system::error_code ec) {
                if (ec == boost::asio::error::operation_aborted)
                {
                    // Host resets more than once while booting. This results in
                    // receiving more than one on/off signal during power on. In
                    // this case first instance of the timer will be aborted.
                    return;
                }
                if (ec)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        (std::string("Timer error: ") + ec.message()).c_str());

                    return;
                }
                bindingPtr->triggerDeviceDiscovery();
            });
        });
}
