/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *   Mupen64plus - egl_windows.cpp                                         *
 *   Mupen64Plus homepage: http://code.google.com/p/mupen64plus/           *
 *   Copyright (C) 2009 Richard Goedeken                                   *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.          *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <EGL/egl.h>
#include <SDL_syswm.h>

#include "egl_windows.h"

/******************************************************************************
 Global variables
******************************************************************************/

// EGL variables
EGLDisplay eglDisplay = 0;
EGLConfig  eglConfig  = 0;
EGLSurface eglSurface = 0;
EGLContext eglContext = 0;

EGLint pi32ConfigAttribs[] = 
{ 
#if GLES_VERSION > 1
    EGL_RED_SIZE,          5, 
    EGL_GREEN_SIZE,        6, 
    EGL_BLUE_SIZE,         5, 
    EGL_ALPHA_SIZE,        0, 
    EGL_DEPTH_SIZE,        24,
    EGL_LEVEL,             0,
    EGL_SURFACE_TYPE,      EGL_WINDOW_BIT,
    EGL_RENDERABLE_TYPE,   EGL_OPENGL_ES2_BIT,
    EGL_NATIVE_RENDERABLE, EGL_FALSE,
    EGL_DEPTH_SIZE,        EGL_DONT_CARE,
    EGL_NONE
#else
    EGL_RED_SIZE,          5, 
    EGL_GREEN_SIZE,        6, 
    EGL_BLUE_SIZE,         5, 
    EGL_ALPHA_SIZE,        0, 
    EGL_DEPTH_SIZE,        24,
    EGL_SURFACE_TYPE,      EGL_WINDOW_BIT, 
    EGL_NONE
#endif
};

extern "C" void create_egl_windows(void)
{
    SDL_SysWMinfo sysInfo; //Will hold our Window information
    SDL_VERSION(&sysInfo.version); //Set SDL version
    if(SDL_GetWMInfo(&sysInfo) <= 0) 
    {
        printf("Unable to get window handle");
        destroy_egl_windows();
    }

    NativeDisplayType natDisplay = GetDC(sysInfo.window);
    NativeWindowType  natWindow  = sysInfo.window;
 
    if (!natDisplay)
    {
        printf("Unable to get display!n");
        destroy_egl_windows();
    }

    if (!natWindow)
    {
        printf("Unable to get window!n");
        destroy_egl_windows();
    }

    eglDisplay = eglGetDisplay((NativeDisplayType) natDisplay);

    if(eglDisplay == EGL_NO_DISPLAY)
        eglDisplay = eglGetDisplay((NativeDisplayType) EGL_DEFAULT_DISPLAY);

    EGLint iMajorVersion, iMinorVersion;
    if (!eglInitialize(eglDisplay, &iMajorVersion, &iMinorVersion))
    {
        printf("eglInitialize() failed.");
        destroy_egl_windows();
    }

#if GLES_VERSION > 1
    eglBindAPI(EGL_OPENGL_ES_API);
#endif

    EGLint iConfigs;
    if (!eglChooseConfig(eglDisplay, pi32ConfigAttribs, &eglConfig, 1, &iConfigs) || (iConfigs != 1))
    {
        printf("eglChooseConfig() failed.");
        destroy_egl_windows();
    }

    eglSurface = eglCreateWindowSurface(eglDisplay, eglConfig, natWindow, NULL);

    if(eglSurface == EGL_NO_SURFACE)
    {
        eglGetError();
        eglSurface = eglCreateWindowSurface(eglDisplay, eglConfig, NULL, NULL);
    }

#if GLES_VERSION > 1
    EGLint ai32ContextAttribs[] = { EGL_CONTEXT_CLIENT_VERSION, GLES_VERSION, EGL_NONE };
    eglContext = eglCreateContext(eglDisplay, eglConfig, NULL, ai32ContextAttribs);
#else
    eglContext = eglCreateContext(eglDisplay, eglConfig, NULL, NULL);
#endif

    eglMakeCurrent(eglDisplay, eglSurface, eglSurface, eglContext);
}

extern "C" void destroy_egl_windows(void)
{
    eglMakeCurrent(eglDisplay, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglTerminate(eglDisplay);
}

extern "C" void egl_swap_buffers(void)
{
    eglSwapBuffers(eglDisplay, eglSurface);
}


