# Real blur + smooth moving hole — implementation reference (for the veil follow-up)

Goal: replace the flat frost with a true Gaussian blur over WhatsApp, with a
crisp spotlight hole that follows the cursor smoothly (no flicker, no lag).

## Chosen technique: Windows.UI.Composition (DWM Visual Layer)

Why: it's the only approach that gives real Gaussian blur AND a flicker-free
moving hole — the hole animates on the compositor thread (a clip), no HWNDs move.
Acrylic tiling and the Magnification lens both move windows per frame → seams /
trailing. `DwmEnableBlurBehindWindow(hRgnBlur)` is a no-op since Win8.

### API sequence (Rust: `windows` crate, features `UI_Composition`, `System`, `Graphics_Effects`, `Foundation_Numerics`, plus DComp/D2D interop)
1. `CreateDispatcherQueueController(DispatcherQueueOptions{ DQTYPE_THREAD_CURRENT, DQTAT_COM_ASTA })` FIRST — Compositor throws without a DispatcherQueue on the thread (RO_E_CLOSED otherwise).
2. `Compositor::new()`.
3. Overlay HWND ex-styles: `WS_EX_NOREDIRECTIONBITMAP | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW`. NOREDIRECTIONBITMAP is required or the backdrop can't show through (black window).
4. `compositor.cast::<ICompositorDesktopInterop>()?.CreateDesktopWindowTarget(hwnd, true)` → set `target.Root(rootVisual)`, root = `CreateContainerVisual` with `RelativeSizeAdjustment({1,1})`.
5. `backdrop = compositor.CreateBackdropBrush()` (via ICompositor2) — LIVE pixels behind. Do NOT use `CreateHostBackdropBrush` (throttled/frozen in Win32).
6. GaussianBlurEffect: not in the `windows` crate (it's a Win2D type). Implement `IGraphicsEffectD2D1Interop` manually as a custom effect descriptor wrapping `CLSID_D2D1GaussianBlur`, property `StandardDeviation`/`BlurAmount` ~24–40, `Source = CompositionEffectSourceParameter("backdrop")`.
7. `factory = compositor.CreateEffectFactory(effect)`; `effectBrush = factory.CreateBrush()`; `effectBrush.SetSourceParameter("backdrop", backdrop)`.
8. `blurVisual = compositor.CreateSpriteVisual()`; `RelativeSizeAdjustment({1,1})`; `Brush(effectBrush)`; `root.Children().InsertAtTop(blurVisual)`.
9. Hole (Option A, lowest latency): `CompositionGeometricClip` on blurVisual whose geometry = outerRect EXCLUDE holeRect (even-odd). Where clipped away → nothing drawn → real window shows crisp through NOREDIRECTIONBITMAP. Recompute geometry on cursor move (cheap); optionally drive the hole rect via a compositor `Vector2/Vector3KeyFrameAnimation` for interpolated motion.
10. Keep overlay glued to the target via `SetWindowPos` + `SetWinEventHook(EVENT_OBJECT_LOCATIONCHANGE)`.

### Top pitfalls
1. Missing `WS_EX_NOREDIRECTIONBITMAP` or using `CreateHostBackdropBrush` → black/frozen overlay.
2. No DispatcherQueue before `Compositor` → immediate throw.
3. `InsetClip` can't punch an inner hole — must use `CompositionGeometricClip` with exclude geometry, or a second clipped crisp-backdrop visual on top.

### Escalation (if overlay can't be guaranteed co-located above target)
Windows.Graphics.Capture: `IGraphicsCaptureItemInterop::CreateForWindow(hwnd)` →
`Direct3D11CaptureFramePool::CreateFreeThreaded` → `StartCapture`, wrap each frame
as `ICompositionSurface`, feed into the GaussianBlur sprite, show the same frame
unblurred in the clipped hole. Fully live, z-order-independent.

Note: capture-based blur will NOT work while WhatsApp is WDA_EXCLUDEFROMCAPTURE
(the capture returns black) — so for WhatsApp specifically, the BackdropBrush
(co-located overlay) path is required, not Graphics.Capture.
