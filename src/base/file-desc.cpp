/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#include "libkazv-config.hpp"

#include <fstream>

#include "file-desc.hpp"
#include "debug.hpp"

namespace Kazv
{
    FileProvider FileDesc::provider(const FileInterface &fh) const
    {
        if (m_inMemory) {
            return FileProvider(DumbFileProvider(m_content));
        }
        return fh.getProviderFor(*this);
    }

    DumbFileProvider DumbFileInterface::getProviderFor(FileDesc desc) const
    {
        using CharT = char;
        auto nameOpt = desc.name();
        kzo.base.dbg() << "DumbFileInterface::getProviderFor()" << std::endl;
        if (! nameOpt) { // should not happen
            kzo.base.dbg() << "No name provided, skip" << std::endl;
            return DumbFileProvider{FileContent{}};
        }

        auto stream = std::ifstream(nameOpt.value(), std::ios_base::binary);
        if (! stream) {
            kzo.base.dbg() << "Cannot open file, skip" << std::endl;
            return DumbFileProvider{FileContent{}};
        }
        auto content = FileContent(std::istreambuf_iterator<CharT>(stream),
                                   std::istreambuf_iterator<CharT>());
        return DumbFileProvider{std::move(content)};
    }

    bool FileDesc::operator==(const FileDesc &that) const
    {
        return m_inMemory == that.m_inMemory
            && m_content == that.m_content
            && m_name == that.m_name
            && m_contentType == that.m_contentType;
    }
}
