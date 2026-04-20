import SwiftUI
import WebKit

struct WebViewRepresentable: UIViewRepresentable {
    let url: URL
    @ObservedObject var browserState: WebBrowserState

    func makeCoordinator() -> Coordinator {
        Coordinator(browserState: browserState, requestedURL: url)
    }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.allowsInlineMediaPlayback = true

        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        context.coordinator.webView = webView
        browserState.webView = webView
        webView.load(URLRequest(url: url))
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        context.coordinator.browserState = browserState
        context.coordinator.webView = webView
        browserState.webView = webView

        if context.coordinator.requestedURL != url {
            context.coordinator.requestedURL = url
            webView.load(URLRequest(url: url))
        }

        DispatchQueue.main.async {
            browserState.update(canGoBack: webView.canGoBack, canGoForward: webView.canGoForward, url: webView.url ?? url)
        }
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        var browserState: WebBrowserState
        var requestedURL: URL
        weak var webView: WKWebView?

        init(browserState: WebBrowserState, requestedURL: URL) {
            self.browserState = browserState
            self.requestedURL = requestedURL
        }

        func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
            browserState.update(canGoBack: webView.canGoBack, canGoForward: webView.canGoForward, url: webView.url)
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            browserState.update(canGoBack: webView.canGoBack, canGoForward: webView.canGoForward, url: webView.url)
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            browserState.update(canGoBack: webView.canGoBack, canGoForward: webView.canGoForward, url: webView.url)
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            browserState.update(canGoBack: webView.canGoBack, canGoForward: webView.canGoForward, url: webView.url)
        }
    }
}

extension WKWebView: WebViewControlling {}
