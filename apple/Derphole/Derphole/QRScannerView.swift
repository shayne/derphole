//
//  QRScannerView.swift
//  Derphole
//
//  Created by Codex on 4/19/26.
//

import AVFoundation
import SwiftUI
import UIKit

struct QRScannerView: UIViewControllerRepresentable {
    let isScanning: Bool
    let onPayload: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onPayload: onPayload)
    }

    func makeUIViewController(context: Context) -> ScannerViewController {
        let controller = ScannerViewController()
        controller.metadataDelegate = context.coordinator
        controller.setScanning(isScanning)
        return controller
    }

    func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {
        context.coordinator.onPayload = onPayload
        uiViewController.metadataDelegate = context.coordinator
        uiViewController.setScanning(isScanning)
    }

    static func dismantleUIViewController(_ uiViewController: ScannerViewController, coordinator: Coordinator) {
        uiViewController.stopScanning()
    }

    final class Coordinator: NSObject, AVCaptureMetadataOutputObjectsDelegate {
        var onPayload: (String) -> Void

        init(onPayload: @escaping (String) -> Void) {
            self.onPayload = onPayload
        }

        func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
            guard
                let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
                object.type == .qr,
                let payload = object.stringValue
            else {
                return
            }
            onPayload(payload)
        }
    }
}

final class ScannerViewController: UIViewController {
    weak var metadataDelegate: AVCaptureMetadataOutputObjectsDelegate?

    private let session = AVCaptureSession()
    private let sessionQueue = DispatchQueue(label: "dev.shayne.derphole.qrscanner")
    private let previewView = CameraPreviewView()
    private let overlayLabel = UILabel()
    private var metadataOutput: AVCaptureMetadataOutput?
    private var didConfigureSession = false
    private var scanningEnabled = true

    override func viewDidLoad() {
        super.viewDidLoad()

        view.backgroundColor = .secondarySystemBackground
        view.layer.cornerRadius = 8
        view.layer.masksToBounds = true

        previewView.translatesAutoresizingMaskIntoConstraints = false
        previewView.previewLayer.videoGravity = .resizeAspectFill
        view.addSubview(previewView)

        overlayLabel.translatesAutoresizingMaskIntoConstraints = false
        overlayLabel.numberOfLines = 0
        overlayLabel.textAlignment = .center
        overlayLabel.textColor = .secondaryLabel
        overlayLabel.font = .preferredFont(forTextStyle: .body)
        overlayLabel.backgroundColor = UIColor.systemBackground.withAlphaComponent(0.86)
        overlayLabel.layer.cornerRadius = 8
        overlayLabel.layer.masksToBounds = true
        overlayLabel.isHidden = true
        view.addSubview(overlayLabel)

        NSLayoutConstraint.activate([
            previewView.topAnchor.constraint(equalTo: view.topAnchor),
            previewView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            previewView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            previewView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            overlayLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            overlayLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            overlayLabel.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])

        #if targetEnvironment(simulator)
        showMessage("Camera scanning is unavailable in the Simulator.\nPaste a payload below to test receive flows.")
        #else
        configureCameraIfNeeded()
        #endif
    }

    func setScanning(_ enabled: Bool) {
        scanningEnabled = enabled
        #if !targetEnvironment(simulator)
        updateRunningState()
        #endif
    }

    func stopScanning() {
        #if !targetEnvironment(simulator)
        sessionQueue.async { [session] in
            if session.isRunning {
                session.stopRunning()
            }
        }
        #endif
    }

    private func configureCameraIfNeeded() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            configureSession()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    guard let self else { return }
                    if granted {
                        self.configureSession()
                    } else {
                        self.showMessage("Camera access is required to scan Derphole receive QR codes.")
                    }
                }
            }
        default:
            showMessage("Camera access is required to scan Derphole receive QR codes.")
        }
    }

    private func configureSession() {
        guard !didConfigureSession else {
            updateRunningState()
            return
        }

        sessionQueue.async { [weak self] in
            guard let self else { return }
            guard let device = AVCaptureDevice.default(for: .video) else {
                DispatchQueue.main.async {
                    self.showMessage("No camera is available on this device.")
                }
                return
            }

            do {
                let input = try AVCaptureDeviceInput(device: device)
                let output = AVCaptureMetadataOutput()

                self.session.beginConfiguration()
                if self.session.canAddInput(input) {
                    self.session.addInput(input)
                }
                if self.session.canAddOutput(output) {
                    self.session.addOutput(output)
                    output.metadataObjectTypes = [.qr]
                    self.metadataOutput = output
                }
                self.session.commitConfiguration()
                self.didConfigureSession = true

                DispatchQueue.main.async {
                    self.previewView.previewLayer.session = self.session
                    if let delegate = self.metadataDelegate, let output = self.metadataOutput {
                        output.setMetadataObjectsDelegate(delegate, queue: .main)
                    }
                    self.hideMessage()
                    self.updateRunningState()
                }
            } catch {
                DispatchQueue.main.async {
                    self.showMessage("Could not start the camera scanner.")
                }
            }
        }
    }

    private func updateRunningState() {
        guard didConfigureSession else { return }

        if let delegate = metadataDelegate, let output = metadataOutput {
            output.setMetadataObjectsDelegate(delegate, queue: .main)
        }

        if scanningEnabled {
            hideMessage()
        } else {
            showMessage("Scanner paused.")
        }

        sessionQueue.async { [session, scanningEnabled] in
            if scanningEnabled {
                if !session.isRunning {
                    session.startRunning()
                }
            } else if session.isRunning {
                session.stopRunning()
            }
        }
    }

    private func showMessage(_ message: String) {
        overlayLabel.text = message
        overlayLabel.isHidden = false
    }

    private func hideMessage() {
        overlayLabel.text = nil
        overlayLabel.isHidden = true
    }
}

private final class CameraPreviewView: UIView {
    override class var layerClass: AnyClass {
        AVCaptureVideoPreviewLayer.self
    }

    var previewLayer: AVCaptureVideoPreviewLayer {
        layer as! AVCaptureVideoPreviewLayer
    }
}
