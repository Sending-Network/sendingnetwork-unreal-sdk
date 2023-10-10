#include <sdn/log.hpp>

#include "spdlog/sinks/stdout_color_sinks.h"

namespace sdn::utils::log {
std::shared_ptr<spdlog::logger>
log()
{
    static auto sdn_logger = std::make_shared<spdlog::logger>(
      "sdn", std::make_shared<spdlog::sinks::stderr_color_sink_mt>());

    return sdn_logger;
}
}
