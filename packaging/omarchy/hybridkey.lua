-- hybridkey QR prompt: small, centred, floating, and hidden from screen shares
-- (the QR code is a live sign-in session while it is on screen).
o.window("^(dev\\.hybridkey\\.Qr)$", { float = true, center = true, no_screen_share = true })
