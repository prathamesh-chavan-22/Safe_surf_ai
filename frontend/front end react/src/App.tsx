import React, { useState, useEffect } from 'react';
import { Shield, Download, Play, CheckCircle, AlertTriangle, Eye, Lock, Zap, Globe, FileX, MousePointer, BookOpen, Users } from 'lucide-react';

function App() {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    setIsVisible(true);
  }, []);

  const features = [
    {
      icon: <Globe className="w-6 h-6" />,
      title: "Real-Time URL Analysis",
      description: "AI-based phishing scan of every visited website with instant threat detection"
    },
    {
      icon: <MousePointer className="w-6 h-6" />,
      title: "Redirect Interception",
      description: "Confirm redirects before they happen to prevent malicious site visits"
    },
    {
      icon: <FileX className="w-6 h-6" />,
      title: "Auto-Download Blocking",
      description: "Stops suspicious files from downloading automatically to your device"
    },
    {
      icon: <Eye className="w-6 h-6" />,
      title: "DOM & Cookie Monitoring",
      description: "Alerts on content manipulation and suspicious cookie behavior"
    },
    {
      icon: <Lock className="w-6 h-6" />,
      title: "Tabnabbing Prevention",
      description: "Stops background tab takeovers and unauthorized page changes"
    },
    {
      icon: <Zap className="w-6 h-6" />,
      title: "Interactive Pop-ups",
      description: "Entry confirmation with draggable status widget for better UX"
    }
  ];

  const installSteps = [
    "Download the ZIP file from the button below",
    "Extract it to a local folder on your computer",
    "Open Chrome and go to chrome://extensions",
    "Enable Developer Mode in the top right corner",
    "Click 'Load Unpacked' and select the extracted folder",
    "Enjoy secure browsing with Phishing Guard!"
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100">
      {/* Header */}
      <header className={`relative overflow-hidden transition-all duration-1000 ${isVisible ? 'translate-y-0 opacity-100' : '-translate-y-10 opacity-0'}`}>
        <div className="absolute inset-0 bg-gradient-to-r from-blue-600 via-blue-700 to-indigo-800"></div>
        <div className="absolute inset-0 bg-black/10"></div>
        <div className="relative container mx-auto px-6 py-20 text-center">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-white/20 backdrop-blur-sm rounded-full mb-6">
            <img src="/logo/logo.png"/>
          </div>
          <h1 className="text-5xl md:text-6xl font-bold text-white mb-4 tracking-tight">
            Phishing Guard
          </h1>
          <p className="text-xl md:text-2xl text-blue-100 max-w-3xl mx-auto leading-relaxed">
            Advanced Real-Time Protection Against Phishing Threats
          </p>
          <div className="mt-8 flex flex-col sm:flex-row gap-4 justify-center">
            <a
              href="https://github.com/prathamesh-chavan-22/Safe_surf_ai/archive/refs/heads/main.zip"
              className="inline-flex items-center px-8 py-4 bg-white text-blue-700 font-semibold rounded-full hover:bg-blue-50 transition-all duration-300 transform hover:scale-105 shadow-lg"
              download
            >
              <Download className="w-5 h-5 mr-2" />
              Download Now
            </a>
            <button
              className="inline-flex items-center px-8 py-4 bg-white/20 backdrop-blur-sm text-white font-semibold rounded-full hover:bg-white/30 transition-all duration-300 border border-white/30"
              onClick={() => document.getElementById('how-it-works-video')?.scrollIntoView({ behavior: 'smooth' })}
            >
              <Play className="w-5 h-5 mr-2" />
              Watch Demo
            </button>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-6 py-16">
        {/* Introduction */}
        <section className={`mb-20 transition-all duration-1000 delay-300 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <div className="max-w-4xl mx-auto text-center">
            <div className="inline-flex items-center px-4 py-2 bg-blue-100 text-blue-800 rounded-full text-sm font-medium mb-6">
              <Lock className="w-4 h-4 mr-2" />
              What is Phishing Guard?
            </div>
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-6">
              Your Smart Defense Against Online Threats
            </h2>
            <p className="text-lg text-gray-600 leading-relaxed">
              Phishing Guard is an intelligent Chrome extension that protects you from fraudulent websites,
              malicious redirects, and unauthorized file downloads. With AI-powered detection and an intuitive
              interface, stay safe while browsing the web with confidence.
            </p>
          </div>
        </section>

        {/* How It Works Video */}
        <section id="how-it-works-video" className={`mb-20 transition-all duration-1000 delay-500 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <div className="bg-white rounded-3xl p-8 md:p-12 shadow-xl border border-gray-100">
            <div className="text-center mb-8">
              <div className="inline-flex items-center px-4 py-2 bg-blue-100 text-blue-800 rounded-full text-sm font-medium mb-6">
                <Play className="w-4 h-4 mr-2" />
                How It Works
              </div>
              <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
                See Phishing Guard in Action
              </h2>
              <p className="text-lg text-gray-600 max-w-2xl mx-auto">
                Watch how our extension seamlessly protects you from phishing attempts and malicious websites in real-time
              </p>
            </div>

            <div className="relative max-w-4xl mx-auto">
              <div className="aspect-video bg-gradient-to-br from-blue-50 to-indigo-100 rounded-2xl overflow-hidden shadow-lg border border-gray-200">
                <video
                  controls
                  className="w-full h-full object-cover"
                  poster="https://images.pexels.com/photos/5380664/pexels-photo-5380664.jpeg?auto=compress&cs=tinysrgb&w=1200&h=675&fit=crop"
                >
                  <source src="/videos/phishing-guard-demo.mp4" type="video/mp4" />
                  <div className="flex items-center justify-center h-full">
                    <div className="text-center">
                      <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-600 text-white rounded-full mb-4">
                        <Play className="w-8 h-8 ml-1" />
                      </div>
                      <p className="text-gray-600 font-medium">Demo Video</p>
                      <p className="text-sm text-gray-500 mt-2">Interactive demonstration of Phishing Guard features</p>
                    </div>
                  </div>
                </video>
              </div>

              {/* Video highlights */}
              <div className="grid md:grid-cols-3 gap-6 mt-8">
                <div className="text-center p-4">
                  <div className="inline-flex items-center justify-center w-12 h-12 bg-blue-100 text-blue-600 rounded-xl mb-3">
                    <Shield className="w-6 h-6" />
                  </div>
                  <h4 className="font-semibold text-gray-900 mb-2">Real-Time Detection</h4>
                  <p className="text-sm text-gray-600">See instant threat analysis as you browse</p>
                </div>
                <div className="text-center p-4">
                  <div className="inline-flex items-center justify-center w-12 h-12 bg-green-100 text-green-600 rounded-xl mb-3">
                    <CheckCircle className="w-6 h-6" />
                  </div>
                  <h4 className="font-semibold text-gray-900 mb-2">User-Friendly Interface</h4>
                  <p className="text-sm text-gray-600">Simple alerts and confirmation dialogs</p>
                </div>
                <div className="text-center p-4">
                  <div className="inline-flex items-center justify-center w-12 h-12 bg-purple-100 text-purple-600 rounded-xl mb-3">
                    <Zap className="w-6 h-6" />
                  </div>
                  <h4 className="font-semibold text-gray-900 mb-2">Lightning Fast</h4>
                  <p className="text-sm text-gray-600">Zero impact on browsing performance</p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Features Grid */}
        <section className={`mb-20 transition-all duration-1000 delay-700 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <div className="text-center mb-12">
            <div className="inline-flex items-center px-4 py-2 bg-green-100 text-green-800 rounded-full text-sm font-medium mb-6">
              <Zap className="w-4 h-4 mr-2" />
              Key Features
            </div>
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Comprehensive Protection Suite
            </h2>
            <p className="text-lg text-gray-600 max-w-2xl mx-auto">
              Advanced security features designed to keep you safe from the latest phishing techniques
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            {features.map((feature, index) => (
              <div
                key={index}
                className="group bg-white rounded-2xl p-8 shadow-lg hover:shadow-xl transition-all duration-300 transform hover:-translate-y-2 border border-gray-100"
              >
                <div className="inline-flex items-center justify-center w-12 h-12 bg-blue-100 text-blue-600 rounded-xl mb-4 group-hover:bg-blue-600 group-hover:text-white transition-all duration-300">
                  {feature.icon}
                </div>
                <h3 className="text-xl font-semibold text-gray-900 mb-3">
                  {feature.title}
                </h3>
                <p className="text-gray-600 leading-relaxed">
                  {feature.description}
                </p>
              </div>
            ))}
          </div>
        </section>

        {/* Understanding Phishing Video */}
        <section className={`mb-20 transition-all duration-1000 delay-900 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <div className="bg-gradient-to-r from-red-50 via-orange-50 to-yellow-50 rounded-3xl p-8 md:p-12 border border-orange-200">
            <div className="text-center mb-8">
              <div className="inline-flex items-center px-4 py-2 bg-orange-100 text-orange-800 rounded-full text-sm font-medium mb-6">
                <AlertTriangle className="w-4 h-4 mr-2" />
                Education Center
              </div>
              <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
                Understanding Phishing Attacks
              </h2>
              <p className="text-lg text-gray-600 max-w-2xl mx-auto">
                Learn about different types of phishing attacks and how to recognize them before they strike
              </p>
            </div>

            <div className="relative max-w-4xl mx-auto">
              <div className="aspect-video bg-gradient-to-br from-orange-100 to-red-100 rounded-2xl overflow-hidden shadow-lg border border-orange-200">
                <video
                  controls
                  className="w-full h-full object-cover"
                //wwposter="https://images.pexels.com/photos/60504/security-protection-anti-virus-software-60504.jpeg?auto=compress&cs=tinysrgb&w=1200&h=675&fit=crop"
                >
                  <source src="/videos/phishing.mp4" type="video/mp4" />
                  <div className="flex items-center justify-center h-full">
                    <div className="text-center">
                      <div className="inline-flex items-center justify-center w-16 h-16 bg-orange-600 text-white rounded-full mb-4">
                        <BookOpen className="w-8 h-8" />
                      </div>
                      <p className="text-gray-700 font-medium">Educational Video</p>
                      <p className="text-sm text-gray-600 mt-2">Learn about phishing threats and protection strategies</p>
                    </div>
                  </div>
                </video>
              </div>

              {/* Educational highlights */}
              <div className="grid md:grid-cols-4 gap-6 mt-8">
                <div className="text-center p-4 bg-white/60 backdrop-blur-sm rounded-xl">
                  <div className="inline-flex items-center justify-center w-12 h-12 bg-red-100 text-red-600 rounded-xl mb-3">
                    <AlertTriangle className="w-6 h-6" />
                  </div>
                  <h4 className="font-semibold text-gray-900 mb-2">Common Threats</h4>
                  <p className="text-sm text-gray-600">Email phishing, fake websites, social engineering</p>
                </div>
                <div className="text-center p-4 bg-white/60 backdrop-blur-sm rounded-xl">
                  <div className="inline-flex items-center justify-center w-12 h-12 bg-yellow-100 text-yellow-600 rounded-xl mb-3">
                    <Eye className="w-6 h-6" />
                  </div>
                  <h4 className="font-semibold text-gray-900 mb-2">Warning Signs</h4>
                  <p className="text-sm text-gray-600">Suspicious URLs, urgent messages, poor grammar</p>
                </div>
                <div className="text-center p-4 bg-white/60 backdrop-blur-sm rounded-xl">
                  <div className="inline-flex items-center justify-center w-12 h-12 bg-blue-100 text-blue-600 rounded-xl mb-3">
                    <Shield className="w-6 h-6" />
                  </div>
                  <h4 className="font-semibold text-gray-900 mb-2">Best Practices</h4>
                  <p className="text-sm text-gray-600">Verify sources, use 2FA, keep software updated</p>
                </div>
                <div className="text-center p-4 bg-white/60 backdrop-blur-sm rounded-xl">
                  <div className="inline-flex items-center justify-center w-12 h-12 bg-green-100 text-green-600 rounded-xl mb-3">
                    <Users className="w-6 h-6" />
                  </div>
                  <h4 className="font-semibold text-gray-900 mb-2">Stay Informed</h4>
                  <p className="text-sm text-gray-600">Latest trends, attack methods, prevention tips</p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Download Section */}
        <section className={`mb-20 transition-all duration-1000 delay-1100 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <div className="bg-gradient-to-r from-blue-600 to-indigo-700 rounded-3xl p-8 md:p-12 text-white">
            <div className="max-w-4xl mx-auto">
              <div className="text-center mb-12">
                <div className="inline-flex items-center px-4 py-2 bg-white/20 backdrop-blur-sm rounded-full text-sm font-medium mb-6">
                  <Download className="w-4 h-4 mr-2" />
                  Get Started
                </div>
                <h2 className="text-3xl md:text-4xl font-bold mb-4">
                  Download & Install
                </h2>
                <p className="text-xl text-blue-100 max-w-2xl mx-auto">
                  Start protecting your browsing experience in just a few simple steps
                </p>
              </div>

              <div className="grid md:grid-cols-2 gap-12 items-center">
                <div>
                  <h3 className="text-2xl font-semibold mb-6">Installation Steps:</h3>
                  <div className="space-y-4">
                    {installSteps.map((step, index) => (
                      <div key={index} className="flex items-start">
                        <div className="flex-shrink-0 w-8 h-8 bg-white/20 backdrop-blur-sm rounded-full flex items-center justify-center text-sm font-semibold mr-4 mt-0.5">
                          {index + 1}
                        </div>
                        <p className="text-blue-100 leading-relaxed">{step}</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="text-center">
                  <div className="bg-white/10 backdrop-blur-sm rounded-2xl p-8 mb-6">
                    <div className="inline-flex items-center justify-center w-16 h-16 bg-white/20 backdrop-blur-sm rounded-full mb-4">
                      <Shield className="w-8 h-8" />
                    </div>
                    <h4 className="text-xl font-semibold mb-2">Latest Version</h4>
                    <p className="text-blue-200 mb-4">v2.1.0 - Enhanced AI Detection</p>
                    <div className="flex items-center justify-center text-sm text-blue-200">
                      <CheckCircle className="w-4 h-4 mr-2" />
                      Virus-free & Open Source
                    </div>
                  </div>

                  <a
                    href="https://github.com/prathamesh-chavan-22/Safe_surf_ai/archive/refs/heads/main.zip"
                    className="inline-flex items-center px-8 py-4 bg-white text-blue-700 font-semibold rounded-full hover:bg-blue-50 transition-all duration-300 transform hover:scale-105 shadow-lg"
                    download
                  >
                    <Download className="w-5 h-5 mr-2" />
                    Download Extension
                  </a>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="bg-gray-900 text-white py-12">
        <div className="container mx-auto px-6">
          <div className="text-center">
            <div className="inline-flex items-center justify-center w-12 h-12 bg-blue-600 rounded-full mb-4">
              <Shield className="w-6 h-6" />
            </div>
            <p className="text-gray-400 mb-4">
              © 2025 Phishing Guard. All rights reserved.
            </p>
            <p className="text-gray-500 text-sm">
              Built with ❤️ to keep you safe online
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;