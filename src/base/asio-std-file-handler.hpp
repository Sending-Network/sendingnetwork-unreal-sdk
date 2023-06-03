/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once
#include "libkazv-config.hpp"

#include <fstream>

#include <boost/asio.hpp>

#include "file-desc.hpp"

namespace Kazv
{
    template<class Exec>
    class AsioStdFileStream
    {
    public:
        using DataT = FileContent;
        /**
         * Constructor.
         *
         * @param exec A boost::asio executor. It should run actions
         * sequentially.
         * @param filename The file name of this FileStream.
         */
        inline AsioStdFileStream(Exec exec, std::string filename, FileOpenMode mode)
            : m_executor(exec)
            , m_filename(filename)
            , m_mode(mode)
            , m_stream(std::make_shared<std::fstream>(
                           m_filename,
                           (m_mode == FileOpenMode::Read
                            ? std::ios_base::in
                            : std::ios_base::out)
                           | std::ios_base::binary))
            {}

        inline bool valid() { return !!m_stream; }

        template<class Callback>
        void read(int maxSize, Callback readCallback) {
            boost::asio::post(
                m_executor,
                [stream=m_stream, maxSize, readCallback=std::move(readCallback)]() {
                    auto buf = std::vector<char>(maxSize, '\0');
                    auto data = FileContent{};
                    auto actualSize = int{};

                    try {
                        stream->read(buf.data(), maxSize);

                        actualSize = stream->gcount();

                        data = FileContent(buf.begin(), buf.begin() + actualSize);
                    } catch (const std::exception &) {
                        readCallback(FileOpRetCode::Error, FileContent{});
                        return;
                    }

                    if (actualSize > 0) {
                        readCallback(FileOpRetCode::Success, data);
                    } else if (stream->eof()) {
                        readCallback(FileOpRetCode::Eof, FileContent{});
                    } else {
                        readCallback(FileOpRetCode::Error, FileContent{});
                    }
                });
        }

        template<class Callback>
        void write(DataT data, Callback writeCallback) {
            boost::asio::post(
                m_executor,
                [stream=m_stream, data, writeCallback=std::move(writeCallback)]() {
                    try {
                        auto buf = std::vector<char>(data.begin(), data.end());
                        stream->write(buf.data(), buf.size());
                    } catch (const std::exception &) {
                        writeCallback(FileOpRetCode::Error, 0);
                        return;
                    }

                    if (stream->bad()) {
                        writeCallback(FileOpRetCode::Error, 0);
                    } else {
                        writeCallback(FileOpRetCode::Success, data.size());
                    }
                });
        }

    private:
        Exec m_executor;
        std::string m_filename;
        FileOpenMode m_mode;
        std::shared_ptr<std::fstream> m_stream;
    };

    template<class Exec>
    class AsioStdFileProvider
    {
    public:
        using FileStreamT = AsioStdFileStream<Exec>;

        /**
         * Constructor.
         *
         * @param exec A boost::asio executor. It should run actions
         * sequentially.
         * @param filename The file name of this FileProvider.
         */
        inline AsioStdFileProvider(Exec exec, std::string filename)
            : m_executor(exec)
            , m_filename(filename)
            {}

        /**
         * Get the FileStream provided by this.
         *
         * @return A FileStreamT that is associated with this file.
         */
        FileStreamT getStream(FileOpenMode mode) const {
            return FileStreamT(m_executor, m_filename, mode);
        }

    private:
        Exec m_executor;
        std::string m_filename;
    };

    template<class Exec>
    class AsioStdFileHandler
    {
    public:
        using FileProviderT = AsioStdFileProvider<Exec>;

        /**
         * Constructor.
         *
         * @param exec A boost::asio executor. It should run actions
         * sequentially.
         */
        inline AsioStdFileHandler(Exec exec)
            : m_executor(exec)
            {}

        /**
         * Get the FileProvider for `desc`.
         *
         * @warning You should not call this explicitly.
         * It should only be called by `desc.provider(*this)`.
         */
        FileProviderT getProviderFor(FileDesc desc) const {
            // assert(desc.name())
            return FileProviderT(m_executor, desc.name().value());
        }
    private:
        Exec m_executor;
    };

    template<class Exec>
    AsioStdFileHandler(Exec)->AsioStdFileHandler<Exec>;
}
