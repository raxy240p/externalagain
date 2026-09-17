#include "Window.hpp"
#include <skCrypter/skCrypter.hpp>

// In release builds, strip all LOGF format strings from .rdata.
// The logging subsystem may still call into Logger internals, but no
// format-string literals are emitted by this translation unit.
#ifdef NDEBUG
#undef LOGF
#define LOGF(...) ((void)0)
#endif

ID3D11Device*            Window::device            = nullptr;
ID3D11DeviceContext*     Window::device_context    = nullptr;
ID3D11RenderTargetView*  Window::render_targetview = nullptr;
IDXGISwapChain*          Window::swap_chain        = nullptr;

bool Window::vsync = false;
HWND Window::hwnd = nullptr;
HWND Window::viewport = nullptr;
WNDCLASSEX Window::wc = { };

extern LRESULT CALLBACK window_procedure(HWND window, UINT msg, WPARAM wParam, LPARAM lParam);

bool Window::CreateDevice()
{
	D3D_FEATURE_LEVEL featureLevel;
	const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };

	HRESULT hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0U,
		featureLevelArray, 2, D3D11_SDK_VERSION, &device, &featureLevel, &device_context);

	if (hr == DXGI_ERROR_UNSUPPORTED)
		hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0U,
			featureLevelArray, 2, D3D11_SDK_VERSION, &device, &featureLevel, &device_context);

	if (FAILED(hr)) {
		LOGF(FATAL, "D3D11CreateDevice failed: 0x{:X}", (unsigned)hr);
		return false;
	}

	int screenW = GetSystemMetrics(SM_CXSCREEN);
	int screenH = GetSystemMetrics(SM_CYSCREEN);

	// Obtain the DXGI factory from the device
	IDXGIDevice*  dxgiDev = nullptr;
	IDXGIAdapter* adapter = nullptr;
	IDXGIFactory* factory = nullptr;
	hr = device->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgiDev);
	if (SUCCEEDED(hr)) hr = dxgiDev->GetAdapter(&adapter);
	if (dxgiDev) dxgiDev->Release();
	if (SUCCEEDED(hr)) hr = adapter->GetParent(__uuidof(IDXGIFactory), (void**)&factory);
	if (adapter) adapter->Release();
	if (FAILED(hr) || !factory) {
		LOGF(FATAL, "IDXGIFactory obtain failed: 0x{:X}", (unsigned)hr);
		return false;
	}

	// Swap chain draws directly to the DWM-transparent overlay window
	DXGI_SWAP_CHAIN_DESC sd                        = {};
	sd.BufferCount                                  = 2;
	sd.BufferDesc.Width                             = (UINT)screenW;
	sd.BufferDesc.Height                            = (UINT)screenH;
	sd.BufferDesc.Format                            = DXGI_FORMAT_B8G8R8A8_UNORM;
	sd.BufferDesc.RefreshRate.Numerator             = 0;
	sd.BufferDesc.RefreshRate.Denominator           = 1;
	sd.BufferUsage                                  = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	sd.OutputWindow                                 = hwnd;
	sd.SampleDesc.Count                             = 1;
	sd.Windowed                                     = TRUE;
	sd.SwapEffect                                   = DXGI_SWAP_EFFECT_DISCARD;

	hr = factory->CreateSwapChain(device, &sd, &swap_chain);
	factory->MakeWindowAssociation(hwnd, DXGI_MWA_NO_ALT_ENTER);
	factory->Release();
	if (FAILED(hr) || !swap_chain) {
		LOGF(FATAL, "CreateSwapChain failed: 0x{:X}", (unsigned)hr);
		return false;
	}

	ID3D11Texture2D* back_buffer = nullptr;
	hr = swap_chain->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&back_buffer);
	if (FAILED(hr) || !back_buffer) {
		LOGF(FATAL, "GetBuffer failed: 0x{:X}", (unsigned)hr);
		return false;
	}
	hr = device->CreateRenderTargetView(back_buffer, nullptr, &render_targetview);
	back_buffer->Release();
	if (FAILED(hr) || !render_targetview) {
		LOGF(FATAL, "CreateRenderTargetView failed: 0x{:X}", (unsigned)hr);
		return false;
	}

	LOGF(VERBOSE, "Created Device (swap chain {}x{} on HWND {:X})", screenW, screenH, (uintptr_t)hwnd);
	return true;
}

void Window::DestroyDevice()
{
	if (render_targetview) { render_targetview->Release(); render_targetview = nullptr; }
	if (swap_chain)        { swap_chain->Release();        swap_chain = nullptr; }

	if (device_context) {
		device_context->ClearState();
		device_context->Flush();
		device_context->Release();
		device_context = nullptr;
	}
	if (device) {
		device->Release();
		device = nullptr;
		LOGF(VERBOSE, "Released Device");
	}
	else
		LOGF(WARNING, "Device Not Found to destroy.");
}

static constexpr int HOTKEY_TOGGLE = 1001;

bool Window::SpawnWindow()
{
	ImGui_ImplWin32_EnableDpiAwareness();

	// Randomize window class name per session so static-string scanners miss it.
	static char s_wndClass[24] = {};
	if (!s_wndClass[0]) {
		DWORD tc = (DWORD)GetTickCount64();
		snprintf(s_wndClass, sizeof(s_wndClass), "%08X%08X", tc, tc ^ 0xBADC0FFEu);
	}

	wc.cbSize = sizeof(wc);
	wc.style = CS_HREDRAW | CS_VREDRAW;
	wc.hInstance = GetModuleHandle(0);
	wc.lpszClassName = s_wndClass;
	wc.lpfnWndProc = window_procedure;
	wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

	RegisterClassEx(&wc);

	int width = GetSystemMetrics(SM_CXSCREEN);
	int height = GetSystemMetrics(SM_CYSCREEN);

	hwnd = CreateWindowEx(
		WS_EX_LAYERED | WS_EX_NOACTIVATE | WS_EX_TRANSPARENT,
		wc.lpszClassName,
		"",
		WS_POPUP | WS_VISIBLE | WS_CLIPSIBLINGS,
		0, 0, width, height,
		NULL, NULL, wc.hInstance, NULL
	);

	if (hwnd == NULL) {
		LOGF(FATAL, "Failed to create Window");
		return false;
	}

	// Raise to top without the TOPMOST flag — z-order is maintained each frame in HandleWindowOrder
	SetWindowPos(hwnd, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

	// Required to activate the layered window before DWM compositor takes over.
	// Without this, WS_EX_LAYERED windows may render black or be invisible.
	SetLayeredWindowAttributes(hwnd, RGB(0, 0, 0), BYTE(255), LWA_ALPHA);

	// DWM glass transparency: extends the compositor frame into the entire client
	// area so D3D alpha=0 pixels become transparent.
	MARGINS margins = { -1, -1, -1, -1 };
	DwmExtendFrameIntoClientArea(hwnd, &margins);

	// Register INSERT as a system hotkey so the toggle is handled via WM_HOTKEY
	// (standard mechanism used by legitimate apps like Discord, Steam overlay).
	RegisterHotKey(hwnd, HOTKEY_TOGGLE, 0, VK_INSERT);

	ShowWindow(hwnd, SW_SHOW);
	UpdateWindow(hwnd);

	LOGF(VERBOSE, "Window Created with HWND {} dimensions {}w {}h", (uintptr_t)hwnd, width, height);
	return true;
}

void Window::DespawnWindow()
{
	UnregisterHotKey(hwnd, HOTKEY_TOGGLE);
	DestroyWindow(hwnd);
	UnregisterClass(wc.lpszClassName, wc.hInstance);
	LOGF(VERBOSE, "Window Despawned");
}

bool Window::CreateImGui()
{
	ImGui::CreateContext();
	ImGui::StyleColorsDark();

	ImGuiIO& io = ImGui::GetIO(); (void)io;
	io.IniFilename = nullptr;
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard | ImGuiConfigFlags_NoMouseCursorChange;

	io.ConfigViewportsNoTaskBarIcon = true;
	io.ConfigViewportsNoAutoMerge = true;

	if (!ImGui_ImplWin32_Init(hwnd)) {
		LOGF(FATAL, "Failed ImGui_ImplWin32_Init");
		return false;
	}

	if (!ImGui_ImplDX11_Init(device, device_context)) {
		LOGF(FATAL, "Failed ImGui_ImplDX11_Init");
		return false;
	}

	LOGF(VERBOSE, "ImGui Initialized");
	return true;
}

void Window::DestroyImGui()
{
	ImGui_ImplDX11_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();
	LOGF(VERBOSE, "Imgui Destroyed");
}

void Window::StartRender()
{
	MSG msg;
	while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
		if (msg.message == WM_QUIT)
			shouldRun = false;
	}

	ImGui_ImplDX11_NewFrame();
	ImGui_ImplWin32_NewFrame();

	// Feed cursor position and mouse buttons globally — no window focus needed.
	{
		auto& io = ImGui::GetIO();
		POINT pt = {};
		if (GetCursorPos(&pt) && ScreenToClient(hwnd, &pt))
			io.AddMousePosEvent((float)pt.x, (float)pt.y);
		static const struct { int vk; ImGuiMouseButton btn; } kButtons[] = {
			{ VK_LBUTTON, ImGuiMouseButton_Left },
			{ VK_RBUTTON, ImGuiMouseButton_Right },
			{ VK_MBUTTON, ImGuiMouseButton_Middle },
		};
		for (auto& b : kButtons) {
			bool down = (GetAsyncKeyState(b.vk) & 0x8000) != 0;
			io.AddMouseButtonEvent(b.btn, down);
		}
	}

	ImGui::NewFrame();
}

void Window::EndRender()
{
	ImGui::Render();

	float color[4]{ 0, 0, 0, 0 };
	device_context->OMSetRenderTargets(1, &render_targetview, nullptr);
	device_context->ClearRenderTargetView(render_targetview, color);
	ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

	swap_chain->Present(vsync ? 1 : 0, 0);

	auto io = ImGui::GetIO();
	if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
		ImGui::UpdatePlatformWindows();
		ImGui::RenderPlatformWindowsDefault();
	}
}

void Window::SetTopMost(HWND window, bool up_down) {
	SetWindowPos(
		window,
		up_down ? HWND_TOPMOST : HWND_NOTOPMOST,
		0, 0, 0, 0,
		SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER
	);
}

void Window::SetClickthrough(HWND window, bool clickthrough)
{
	LONG_PTR style = GetWindowLongPtr(window, GWL_EXSTYLE);
	// Toggle both WS_EX_TRANSPARENT and WS_EX_NOACTIVATE together (Valthrun pattern):
	// when the menu is open the overlay needs to receive mouse/keyboard input,
	// so both flags must be cleared; when closed they are re-applied for full pass-through.
	if (clickthrough)
		style |=  (WS_EX_TRANSPARENT | WS_EX_NOACTIVATE);
	else
		style &= ~(WS_EX_TRANSPARENT | WS_EX_NOACTIVATE);
	SetWindowLongPtr(window, GWL_EXSTYLE, style);
}

void Window::SetBounds(HWND window, RECT bounds) {
	SetWindowPos(
		window,
		nullptr,
		bounds.left, bounds.top,
		bounds.right - bounds.left,
		bounds.bottom - bounds.top,
		SWP_NOZORDER | SWP_NOACTIVATE
	);
	UpdateWindow(window);
}

bool Window::SetAffinity(HWND window, WindowAffinity afi) {
	auto mode = WDA_NONE;
	std::string mode_str = "Disabled";

	switch (afi) {
	case WindowAffinity::Black:
		mode = WDA_MONITOR;
		mode_str = "Black";
		break;
	case WindowAffinity::Invisible:
		mode = WDA_EXCLUDEFROMCAPTURE;
		mode_str = "Invisible";
		break;
	default:
		mode = WDA_NONE;
		mode_str = "Disabled";
		break;
	}

	auto status = SetWindowDisplayAffinity(window, mode);

	if (status)
		LOGF(VERBOSE, "Set Window Affinity to " + mode_str);
	else
		LOGF(FATAL, "Failed to set Window Affinity to " + mode_str);

	return status;
}

void Window::SetForeground(HWND window) {
	if (!IsWindowInForeground(window))
		BringToForeground(window);
}

void Window::SetVSync(bool enable) {
	vsync = enable;
	LOGF(VERBOSE, "VSync is now {}", enable ? "Enabled" : "Disabled");
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT CALLBACK window_procedure(HWND window, UINT msg, WPARAM wParam, LPARAM lParam)
{
	// With WS_EX_TRANSPARENT set (menu closed), WM_MOUSEACTIVATE is never sent,
	// so we don't need to return MA_NOACTIVATE anymore. When menu is open and
	// WS_EX_TRANSPARENT is cleared, we still want normal ImGui mouse handling.

	// Guarantee click-through whenever WS_EX_TRANSPARENT is set.
	if (msg == WM_NCHITTEST)
	{
		if (GetWindowLongPtrA(window, GWL_EXSTYLE) & WS_EX_TRANSPARENT)
			return HTTRANSPARENT;
	}

	if (ImGui_ImplWin32_WndProcHandler(window, msg, wParam, lParam))
		return true;

	switch (msg)
	{
	case WM_SYSCOMMAND:
		if ((wParam & 0xfff0) == SC_KEYMENU)
			return 0;
		break;
	case WM_HOTKEY:
		if ((int)wParam == HOTKEY_TOGGLE) {
			Window::togglePending = true;
			LOGF(VERBOSE, "WM_HOTKEY toggle received");
		}
		return 0;
	case WM_DESTROY:
		LOGF(VERBOSE, "Window procedure WM_DESTROY event triggered");
		break;
	case WM_CLOSE:
		LOGF(VERBOSE, "Window procedure WM_CLOSE event triggered");
		Window::shouldRun = false;
		break;
	case WM_SIZE:
		if (Window::device != nullptr && wParam != SIZE_MINIMIZED) {
			// Unbind render target BEFORE releasing — ResizeBuffers fails if
			// the device context still holds a reference to the back buffer.
			Window::device_context->OMSetRenderTargets(0, nullptr, nullptr);
			if (Window::render_targetview) {
				Window::render_targetview->Release();
				Window::render_targetview = nullptr;
			}
			Window::swap_chain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
			ID3D11Texture2D* back_buffer = nullptr;
			Window::swap_chain->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&back_buffer);
			if (back_buffer) {
				HRESULT hr = Window::device->CreateRenderTargetView(back_buffer, nullptr, &Window::render_targetview);
				back_buffer->Release();
				if (FAILED(hr))
					Window::render_targetview = nullptr;
			}
		}
		return 0;
	case WM_DPICHANGED:
		LOGF(VERBOSE, "Window procedure WM_DPICHANGED event triggered");
		if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_DpiEnableScaleViewports)
		{
			const RECT* suggested_rect = (RECT*)lParam;
			SetWindowPos(
				Window::hwnd,
				nullptr,
				suggested_rect->left, suggested_rect->top,
				suggested_rect->right - suggested_rect->left,
				suggested_rect->bottom - suggested_rect->top,
				SWP_NOZORDER | SWP_NOACTIVATE
			);
		}
		break;
	}

	return DefWindowProc(window, msg, wParam, lParam);
}
