/*
 * Copyright (c) 2024, Andrew Kaster <akaster@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Optional.h>
#include <AK/Types.h>
#include <LibGfx/Size.h>
#include <LibIPC/Forward.h>
#include <LibWebCommon/Export.h>
#include <LibWebCommon/HTML/CrossProcessId.h>
#include <LibWebCommon/PixelUnits.h>

namespace Web::HTML {

struct PictureInPictureWindowHints {
    // The navigable whose active document requests the window for one of its videos.
    CrossProcessId navigable_id;
    Gfx::IntSize video_size;
};

struct WebViewHints {
    bool popup = false;
    Optional<PictureInPictureWindowHints> picture_in_picture_window;
    Optional<DevicePixels> width;
    Optional<DevicePixels> height;
    Optional<DevicePixels> screen_x;
    Optional<DevicePixels> screen_y;
    // A WebDriver BiDi browsingContext.create of type "window" wants its own OS window, not a tab.
    bool new_window = false;
    // The WebDriver BiDi browsingContext.create this window is for, if any: the UI process lets that request, and no
    // pop-up of the page, through the pop-up blocker.
    Optional<u64> webdriver_open_id;
};

}

namespace IPC {

template<>
WEBCOMMON_API ErrorOr<void> encode(Encoder&, Web::HTML::PictureInPictureWindowHints const&);

template<>
WEBCOMMON_API ErrorOr<Web::HTML::PictureInPictureWindowHints> decode(Decoder&);

template<>
WEBCOMMON_API ErrorOr<void> encode(Encoder&, Web::HTML::WebViewHints const&);

template<>
WEBCOMMON_API ErrorOr<Web::HTML::WebViewHints> decode(Decoder&);

}
