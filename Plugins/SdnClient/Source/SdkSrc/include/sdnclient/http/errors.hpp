#pragma once

/// @file
/// @brief Error codes returned by the client-server API

#include <optional>

#include <spdlog/common.h>

#include "sdn/errors.hpp"

namespace sdn {
namespace http {

//! Compound type that includes sdn & network related errors.
struct ClientError
{
    //! client api related error.
    sdn::errors::Error sdn_error;
    //! Error code if a network related error occured.
    int error_code;
    //! Status code of the associated http response.
    int status_code;
    //! Parsing response error.
    std::string parse_error;

    const char *error_code_string() const;
};
} // namespace http
} // namespace sdn

template<>
struct fmt::formatter<sdn::http::ClientError>
{
    // Presentation format: 'f' - fixed, 'e' - exponential.
    bool print_network_error = false;
    bool print_http_error    = false;
    bool print_parser_error  = false;
    bool print_sdn_error  = false;

    // Parses format specifications of the form ['f' | 'e'].
    constexpr auto parse(fmt::format_parse_context &ctx) -> decltype(ctx.begin())
    {
        // [ctx.begin(), ctx.end()) is a character range that contains a part of
        // the format string starting from the format specifications to be parsed,
        // e.g. in
        //
        //   fmt::format("{:f} - point of interest", point{1, 2});
        //
        // the range will contain "f} - point of interest". The formatter should
        // parse specifiers until '}' or the end of the range. In this example
        // the formatter should parse the 'f' specifier and return an iterator
        // pointing to '}'.

        // Parse the presentation format and store it in the formatter:
        auto it = ctx.begin(), end = ctx.end();

        while (it != end && *it != '}') {
            auto tmp = *it++;

            switch (tmp) {
            case 'n':
                print_network_error = true;
                break;
            case 'h':
                print_http_error = true;
                break;
            case 'p':
                print_parser_error = true;
                break;
            case 'm':
                print_sdn_error = true;
                break;
            default:
                throw format_error("invalid format specifier for sdn error");
            }
        }

        // Check if reached the end of the range:
        if (it != end && *it != '}')
            throw fmt::format_error("invalid format");

        // Return an iterator past the end of the parsed range:
        return it;
    }

    // Formats the point p using the parsed format specification (presentation)
    // stored in this formatter.
    template<typename FormatContext>
    auto format(const sdn::http::ClientError &e, FormatContext &ctx) -> decltype(ctx.out())
    {
        // ctx.out() is an output iterator to write to.
        bool prepend_comma = false;
        fmt::format_to(ctx.out(), "(");
        if (print_network_error || e.error_code) {
            fmt::format_to(ctx.out(), "connection: {}", e.error_code_string());
            prepend_comma = true;
        }

        if (print_http_error ||
            (e.status_code != 0 && (e.status_code < 200 || e.status_code >= 300))) {
            if (prepend_comma)
                fmt::format_to(ctx.out(), ", ");
            fmt::format_to(ctx.out(), "http: {}", e.status_code);
            prepend_comma = true;
        }

        if (print_parser_error || !e.parse_error.empty()) {
            if (prepend_comma)
                fmt::format_to(ctx.out(), ", ");
            fmt::format_to(ctx.out(), "parser: {}", e.parse_error);
            prepend_comma = true;
        }

        if (print_parser_error ||
            (e.sdn_error.errcode != sdn::errors::ErrorCode::M_UNRECOGNIZED &&
             !e.sdn_error.error.empty())) {
            if (prepend_comma)
                fmt::format_to(ctx.out(), ", ");
            fmt::format_to(ctx.out(),
                           "sdn: {}:'{}'",
                           to_string(e.sdn_error.errcode),
                           e.sdn_error.error);
        }

        return fmt::format_to(ctx.out(), ")");
    }
};

template<>
struct fmt::formatter<std::optional<sdn::http::ClientError>> : formatter<sdn::http::ClientError>
{
    // parse is inherited from formatter<string_view>.
    template<typename FormatContext>
    auto format(std::optional<sdn::http::ClientError> c, FormatContext &ctx)
    {
        if (!c)
            return fmt::format_to(ctx.out(), "(no error)");
        else
            return formatter<sdn::http::ClientError>::format(*c, ctx);
    }
};
