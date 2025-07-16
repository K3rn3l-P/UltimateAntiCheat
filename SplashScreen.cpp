#include "SplashScreen.hpp"
#include "resource.h"

void Splash::InitializeSplash()
{
    const int splashDisplayTime = 5000;

    GdiplusStartupInput gdiplusStartupInput;    // Initialize GDI+
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);

    HINSTANCE hInstance = GetModuleHandle(nullptr);

    HWND splashWnd = CreateSplashWindow(hInstance);
    ShowWindow(splashWnd, SW_SHOW);
    UpdateWindow(splashWnd);

    Sleep(splashDisplayTime); // Sleep for 5 seconds

    // Hide and destroy splash window
    DestroyWindow(splashWnd);

    // Shutdown GDI+
    GdiplusShutdown(gdiplusToken);
}

void Splash::PositionWindow(HWND hwnd)
{
    RECT rc;
    GetWindowRect(hwnd, &rc);

    RECT workArea;
    SystemParametersInfo(SPI_GETWORKAREA, 0, &workArea, 0); // area senza taskbar 

    int windowWidth = rc.right - rc.left;
    int windowHeight = rc.bottom - rc.top;

    int x = workArea.right - windowWidth;
    int y = workArea.bottom - windowHeight;

    SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOZORDER | SWP_NOSIZE | SWP_NOACTIVATE);
}

HWND Splash::CreateSplashWindow(HINSTANCE hInstance) 
{
    const wchar_t CLASS_NAME[] = L"SplashWindowClass";

    WNDCLASS wc = {};
    wc.lpfnWndProc = SplashWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(0,CLASS_NAME,nullptr,WS_POPUP, CW_USEDEFAULT, CW_USEDEFAULT, 250, 250,  nullptr,nullptr, hInstance, nullptr);

    PositionWindow(hwnd);

    return hwnd;
}

LRESULT CALLBACK Splash::SplashWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) 
{
    switch (message) 
    {
    case WM_PAINT: 
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        Graphics graphics(hdc);

        HRSRC hResource = FindResource(GetModuleHandle(nullptr), MAKEINTRESOURCE(IDR_SPLASH_IMAGE), RT_RCDATA);
        if (!hResource) {
            Logger::logf(Warning, "Failed to load splash screen resource.");
            EndPaint(hWnd, &ps);
            break;
        }

        DWORD imageSize = SizeofResource(GetModuleHandle(nullptr), hResource);
        HGLOBAL hLoadedResource = LoadResource(GetModuleHandle(nullptr), hResource);
        void* pResourceData = LockResource(hLoadedResource);

        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, imageSize);
        if (!hMem) {
            Logger::logf(Warning, "Failed to allocate memory for splash image.");
            EndPaint(hWnd, &ps);
            break;
        }
        void* pMem = GlobalLock(hMem);
        memcpy(pMem, pResourceData, imageSize);
        GlobalUnlock(hMem);

        IStream* pStream = nullptr;
        HRESULT hr = CreateStreamOnHGlobal(hMem, TRUE, &pStream); // TRUE: lo stream libera hMem
        if (FAILED(hr) || !pStream) {
            Logger::logf(Warning, "Failed to create stream for splash screen resource.");
            GlobalFree(hMem);
            EndPaint(hWnd, &ps);
            break;
        }

        Image image(pStream);
        pStream->Release();

        UINT imgWidth = image.GetWidth();
        UINT imgHeight = image.GetHeight();

        if (imgWidth == 0 || imgHeight == 0) {
            Logger::logf(Warning, "Failed to load splash screen image.");
            EndPaint(hWnd, &ps);
            break;
        }

        RECT rect;
        GetClientRect(hWnd, &rect);
        int winWidth = rect.right - rect.left;
        int winHeight = rect.bottom - rect.top;

        float imgAspect = (float)imgWidth / imgHeight;
        float winAspect = (float)winWidth / winHeight;

        int drawWidth, drawHeight;
        int offsetX = 0, offsetY = 0;

        if (winAspect > imgAspect) {
            drawHeight = winHeight;
            drawWidth = (int)(drawHeight * imgAspect);
            offsetX = (winWidth - drawWidth) / 2;
        } else {
            drawWidth = winWidth;
            drawHeight = (int)(drawWidth / imgAspect);
            offsetY = (winHeight - drawHeight) / 2;
        }

        graphics.DrawImage(&image, offsetX, offsetY, drawWidth, drawHeight);

        EndPaint(hWnd, &ps);
        break;
    }
    case WM_CLOSE: 
    {
        DestroyWindow(hWnd);
    } break;
    case WM_DESTROY: 
    {
        PostQuitMessage(0);
    } break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}