//
//  DeceiptFrameSender.swift
//  Deceipt iOS native adapter (A4)
//
//  Bounded sender window with backpressure and bounded retransmission
//  (framing.md §4). At most WINDOW_FRAMES frames are in flight beyond
//  highest_contiguous_sequence; a missing ACK past T_ACK_WAIT triggers a retry
//  from `highest_contiguous + 1`; after MAX_FRAME_RETRIES the transfer is
//  abandoned as TRANSFER_RETRY_EXHAUSTED.
//

import Foundation

public final class FrameSender {
    private let frames: [DataFrame]
    private weak var transport: DeceiptTransport?
    private let window: Int
    private let ackWaitMs: Int
    private let maxRetries: Int

    private var highestContiguous: Int64 = -1
    private var nextToSend = 0
    private var retries = 0
    private var completed = false
    private var paused = false
    private var timer: DispatchSourceTimer?

    public var onProgress: ((Int64, Int) -> Void)?
    public var onExhausted: (() -> Void)?
    private var onComplete: (() -> Void)?

    public init(frames: [DataFrame], transport: DeceiptTransport, window: Int,
                ackWaitMs: Int = DeceiptTimeout.defaults["T_ACK_WAIT"]!,
                maxRetries: Int = DeceiptBounds.maxFrameRetries,
                onProgress: ((Int64, Int) -> Void)? = nil,
                onExhausted: (() -> Void)? = nil) {
        self.frames = frames
        self.transport = transport
        self.window = window
        self.ackWaitMs = ackWaitMs
        self.maxRetries = maxRetries
        self.onProgress = onProgress
        self.onExhausted = onExhausted
    }

    public func start(onComplete: @escaping () -> Void) {
        self.onComplete = onComplete
        pump()
        scheduleAckWait()
    }

    /// Sends as many frames as the window and transport backpressure allow.
    private func pump() {
        guard !completed, let transport else { return }
        while nextToSend < frames.count {
            let inFlight = Int64(nextToSend) - highestContiguous - 1
            if inFlight >= Int64(window) { paused = true; return }
            let ok = transport.sendData(frames[nextToSend].encoded)
            if !ok {
                // Backpressure: stop and let the transport call resumeSending().
                paused = true
                scheduleBackpressureRetry()
                return
            }
            nextToSend += 1
        }
        paused = false
    }

    /// Transport signalled it can accept writes again.
    public func resumeSending() {
        paused = false
        pump()
    }

    public func acknowledge(highestContiguous seq: Int64) {
        guard seq > highestContiguous else { return } // monotonic non-decreasing
        highestContiguous = min(seq, Int64(frames.count - 1))
        retries = 0
        onProgress?(highestContiguous, frames.count)
        if highestContiguous == Int64(frames.count - 1) {
            finish()
            return
        }
        pump()
        scheduleAckWait()
    }

    public func retransmit(from seq: Int64) {
        guard seq >= 0, seq < Int64(frames.count) else { return }
        nextToSend = Int(seq)
        pump()
    }

    private func finish() {
        guard !completed else { return }
        completed = true
        timer?.cancel(); timer = nil
        onComplete?()
    }

    private func scheduleAckWait() {
        timer?.cancel()
        guard !completed else { return }
        let t = DispatchSource.makeTimerSource(queue: .main)
        t.schedule(deadline: .now() + .milliseconds(ackWaitMs))
        t.setEventHandler { [weak self] in
            guard let self, !self.completed else { return }
            // No ACK progress within T_ACK_WAIT: retransmit from the resume point.
            self.retries += 1
            if self.retries > self.maxRetries {
                self.completed = true
                self.timer?.cancel(); self.timer = nil
                self.onExhausted?()
                return
            }
            self.nextToSend = Int(self.highestContiguous + 1)
            self.pump()
            self.scheduleAckWait()
        }
        t.resume()
        timer = t
    }

    private func scheduleBackpressureRetry() {
        guard !completed else { return }
        let t = DispatchSource.makeTimerSource(queue: .main)
        t.schedule(deadline: .now() + .milliseconds(50))
        t.setEventHandler { [weak self] in
            guard let self, !self.completed, self.paused else { return }
            self.pump()
            if self.paused { self.scheduleBackpressureRetry() }
        }
        t.resume()
    }

    public func stop() {
        completed = true
        timer?.cancel(); timer = nil
    }
}
