//
// Created by mgr on 1/31/23.
//

// #define USE_OPENSSL

#include <stdlib.h>

#include <string>
#include <iostream>
#include <thread>
#include <memory>
#include <mutex>

#include <sstream>
#include <deque>
#include <algorithm>
#include <cstring>
#include <limits>

#include <openvpn/common/platform.hpp>


#include <openvpn/common/platform.hpp>

#ifdef OPENVPN_PLATFORM_MAC
#include <CoreFoundation/CFBundle.h>
#include <ApplicationServices/ApplicationServices.h>
#endif

// If enabled, don't direct ovpn3 core logging to
// ClientAPI::OpenVPNClient::log() virtual method.
// Instead, logging will go to LogBaseSimple::log().
// In this case, make sure to define:
//   LogBaseSimple log;
// at the top of your main() function to receive
// log messages from all threads.
// Also, note that the OPENVPN_LOG_GLOBAL setting
// MUST be consistent across all compilation units.
#ifdef OPENVPN_USE_LOG_BASE_SIMPLE
#define OPENVPN_LOG_GLOBAL // use global rather than thread-local log object pointer
#include <openvpn/log/logbasesimple.hpp>
#endif

// don't export core symbols
#define OPENVPN_CORE_API_VISIBILITY_HIDDEN

// use SITNL on Linux by default
#if defined(OPENVPN_PLATFORM_LINUX) && !defined(OPENVPN_USE_IPROUTE2) && !defined(OPENVPN_USE_SITNL)
#define OPENVPN_USE_SITNL
#endif

// should be included before other openvpn includes,
// with the exception of openvpn/log includes
#include <client/ovpncli.cpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/signal.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/getopt.hpp>
#include <openvpn/common/getpw.hpp>
#include <openvpn/common/cleanup.hpp>
#include <openvpn/time/timestr.hpp>
#include <openvpn/ssl/peerinfo.hpp>
#include <openvpn/ssl/sslchoose.hpp>

#ifdef OPENVPN_REMOTE_OVERRIDE
#include <openvpn/common/process.hpp>
#endif

#if defined(USE_MBEDTLS)
#include <openvpn/mbedtls/util/pkcs1.hpp>
#elif defined(USE_OPENSSL)
#include <openssl/evp.h>
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/core_names.h>
#endif
#endif

#if defined(OPENVPN_PLATFORM_WIN)
#include <openvpn/win/console.hpp>
#include <shellapi.h>
#endif

#ifdef USE_NETCFG
#include "client/core-client-netcfg.hpp"
#endif

#if defined(OPENVPN_PLATFORM_LINUX)

#include <openvpn/tun/linux/client/tuncli.hpp>

// we use a static polymorphism and define a
// platform-specific TunSetup class, responsible
// for setting up tun device
#define TUN_CLASS_SETUP TunLinuxSetup::Setup<TUN_LINUX>
#include <openvpn/tun/linux/client/tuncli.hpp>
#elif defined(OPENVPN_PLATFORM_MAC)
#include <openvpn/tun/mac/client/tuncli.hpp>
#define TUN_CLASS_SETUP TunMac::Setup
#endif

using namespace openvpn;

typedef OpenSSLCryptoAPI ClientCryptoAPI;
typedef OpenSSLContext ClientSSLAPI;
typedef OpenSSLRandom ClientRandomAPI;

#define PROTO_CIPHER "AES-128-CBC"
#define PROTO_DIGEST "SHA1"
#define TLS_VER_MIN TLSVersion::UNDEF
#define COMP_METH CompressContext::LZO_STUB
#define TLS_TIMEOUT_CLIENT 2000
#define RENEG 900

class MySessionStats : public SessionStats
{
public:
  typedef RCPtr<MySessionStats> Ptr;

  MySessionStats()
  {
    std::memset(errors, 0, sizeof(errors));
  }

  virtual void error(const size_t err_type, const std::string* text=nullptr)
  {
    if (err_type < Error::N_ERRORS)
      ++errors[err_type];
  }

  count_t get_error_count(const Error::Type type) const
  {
    if (type < Error::N_ERRORS)
      return errors[type];
    else
      return 0;
  }

  void show_error_counts() const
  {
    for (size_t i = 0; i < Error::N_ERRORS; ++i)
      {
	count_t c = errors[i];
	if (c)
	  std::cerr << Error::name(i) << " : " << c << std::endl;
      }
  }

private:
  count_t errors[Error::N_ERRORS];
};

class ClientBase : public ClientAPI::OpenVPNClient
{
  public:
    bool socket_protect(int socket, std::string remote, bool ipv6) override
    {
        std::cout << "NOT IMPLEMENTED: *** socket_protect " << socket << " " << remote << std::endl;
        return true;
    }
};

class Client : public ClientBase
{
    public:
    Client(): ClientBase()
    {
       state->allow_local_dns_resolvers = true;
       state->allow_local_lan_access = true;
       state->allowUnusedAddrFamilies = TriStateSetting::parse("yes");
    //    state->altProxy = true;
       state->autologin_sessions = false;
       state->clock_tick_ms = 0;
    //    state->compressionMode = "yes";
       state->conn_timeout = 5000;
    //    state->contentList = true;
       state->dco = false;
       state->default_key_direction = -1;
       state->disable_client_cert = false;
       state->echo = true;
       state->enable_legacy_algorithms = true;
       state->enable_nonpreferred_dcalgs = true;
       state->external_pki_alias = "USER001"; // dummy string
       state->generate_tun_builder_capture_event = true;
       state->google_dns_fallback = true;
    //    state->gremlinConfig = true;
    //    state->guiVersion = true;
    //    state->hwAddrOverride = true;
    //    state->info = true;
    //    state->peerInfo = true;
    //    state->platformVersion = true;
    //    state->port_override = "11194";
       state->port_override = "1194";
    //    state->privateKeyPassword = true;
    //    state->protoOverride = true;
       state->proto_version_override = IP::Addr::Version::V4;
    //    state->proxyAllowCleartextAuth = false;
    //    state->proxyHost = true;
    //    state->proxyPassword = true;
    //    state->proxyPort = true;
    //    state->proxyUsername = true;
    //    state->retryOnAuthFailed = true;
    //    state->server_override = "127.0.0.1";
       state->server_override = "192.168.1.114";
       state->ssl_debug_level = 3;
    //    state->ssoMethods = true;
       state->synchronous_dns_lookup = true;
    //    state->tlsCertProfileOverride = true;
    //    state->tlsCipherList = true;
    //    state->tlsCiphersuitesList = true;
       state->tls_version_min_override = "tls_1_2";
       state->tun_persist = false;
       state->wintun = false;

        Option oClient;
        oClient.push_back("client");
        oClient.push_back("yes");
        state->options.add_item(oClient);

        Option oServerPollTimeout;
        oServerPollTimeout.push_back("server-poll-timeout");
        oServerPollTimeout.push_back("4");
        state->options.add_item(oServerPollTimeout);

        // Option oNoBind;
        // oNoBind.push_back("nobind");
        // oNoBind.push_back("true");
        // state->options.add_item(oNoBind);

        // Option oRemoteOverride;
        // oRemoteOverride.push_back("remote-override");
        // oRemoteOverride.push_back("remote 192.168.1.114 1194 udp");
        // state->options.add_item(oRemoteOverride);

        Option oRemote;
        oRemote.push_back("remote");
        // oRemote.push_back("192.168.1.114 1194 udp");
        oRemote.push_back("127.0.0.1 11194 udp");
        state->options.add_item(oRemote);

        Option oRemoteCertTls;
        oRemoteCertTls.push_back("remote-cert-tls");
        oRemoteCertTls.push_back("server");
        state->options.add_item(oRemoteCertTls);

        Option oPushPeerInfo;
        oPushPeerInfo.push_back("push-peer-info");
        oPushPeerInfo.push_back("yes");
        state->options.add_item(oPushPeerInfo);

        Option oRenegSec;
        oRenegSec.push_back("reneg-sec");
        oRenegSec.push_back("604800");
        state->options.add_item(oRenegSec);

        // Option oCompLzo;
        // oCompLzo.push_back("comp-lzo");
        // oCompLzo.push_back("no");
        // state->options.add_item(oCompLzo);

        // Option oKeepAlive;
        // oKeepAlive.push_back("keepalive");
        // oKeepAlive.push_back("10 120");
        // state->options.add_item(oKeepAlive);

        Option oDev;
        oDev.push_back("dev");
        oDev.push_back("tun");
        // oDev.push_back("udp-tun");
        state->options.add_item(oDev);

        Option oDevType;
        oDevType.push_back("dev-type");
        oDevType.push_back("tun");
        state->options.add_item(oDevType);

    // const std::string caVal = read_text("/home/mgr/openvpn-related/my-tests/ca.crt");
    // const std::string certVal = read_text("/home/mgr/openvpn-related/my-tests/UAK01.crt");
    // const std::string keyVal = read_text("/home/mgr/openvpn-related/my-tests/UAK01.key");

    const std::string caVal = read_text("/home/mgr/openvpn-related/ca.crt");
    const std::string certVal = read_text("/home/mgr/openvpn-related/client.crt");
    const std::string keyVal = read_text("/home/mgr/openvpn-related/client.key");

//         std::string caVal = std::string("-----BEGIN CERTIFICATE-----\n"
// "MIIGKDCCBBCgAwIBAgIJAKFO3vqQ8q6BMA0GCSqGSIb3DQEBCwUAMGYxCzAJBgNV\n"
// "BAYTAktHMQswCQYDVQQIEwJOQTEQMA4GA1UEBxMHQklTSEtFSzEVMBMGA1UEChMM\n"
// "T3BlblZQTi1URVNUMSEwHwYJKoZIhvcNAQkBFhJtZUBteWhvc3QubXlkb21haW4w\n"
// "HhcNMTQxMDIyMjE1OTUyWhcNMjQxMDE5MjE1OTUyWjBmMQswCQYDVQQGEwJLRzEL\n"
// "MAkGA1UECBMCTkExEDAOBgNVBAcTB0JJU0hLRUsxFTATBgNVBAoTDE9wZW5WUE4t\n"
// "VEVTVDEhMB8GCSqGSIb3DQEJARYSbWVAbXlob3N0Lm15ZG9tYWluMIICIjANBgkq\n"
// "hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsJVPCqt3vtoDW2U0DII1QIh2Qs0dqh88\n"
// "8nivxAIm2LTq93e9fJhsq3P/UVYAYSeCIrekXypR0EQgSgcNTvGBMe20BoHO5yvb\n"
// "GjKPmjfLj6XRotCOGy8EDl/hLgRY9efiA8wsVfuvF2q/FblyJQPR/gPiDtTmUiqF\n"
// "qXa7AJmMrqFsnWppOuGd7Qc6aTsae4TF1e/gUTCTraa7NeHowDaKhdyFmEEnCYR5\n"
// "CeUsx2JlFWAH8PCrxBpHYbmGyvS0kH3+rQkaSM/Pzc2bS4ayHaOYRK5XsGq8XiNG\n"
// "KTTLnSaCdPeHsI+3xMHmEh+u5Og2DFGgvyD22gde6W2ezvEKCUDrzR7bsnYqqyUy\n"
// "n7LxnkPXGyvR52T06G8KzLKQRmDlPIXhzKMO07qkHmIonXTdF7YI1azwHpAtN4dS\n"
// "rUe1bvjiTSoEsQPfOAyvD0RMK/CBfgEZUzAB50e/IlbZ84c0DJfUMOm4xCyft1HF\n"
// "YpYeyCf5dxoIjweCPOoP426+aTXM7kqq0ieIr6YxnKV6OGGLKEY+VNZh1DS7enqV\n"
// "HP5i8eimyuUYPoQhbK9xtDGMgghnc6Hn8BldPMcvz98HdTEH4rBfA3yNuCxLSNow\n"
// "4jJuLjNXh2QeiUtWtkXja7ec+P7VqKTduJoRaX7cs+8E3ImigiRnvmK+npk7Nt1y\n"
// "YE9hBRhSoLsCAwEAAaOB2DCB1TAdBgNVHQ4EFgQUK0DlyX319JY46S/jL9lAZMmO\n"
// "BZswgZgGA1UdIwSBkDCBjYAUK0DlyX319JY46S/jL9lAZMmOBZuhaqRoMGYxCzAJ\n"
// "BgNVBAYTAktHMQswCQYDVQQIEwJOQTEQMA4GA1UEBxMHQklTSEtFSzEVMBMGA1UE\n"
// "ChMMT3BlblZQTi1URVNUMSEwHwYJKoZIhvcNAQkBFhJtZUBteWhvc3QubXlkb21h\n"
// "aW6CCQChTt76kPKugTAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG\n"
// "9w0BAQsFAAOCAgEABc77f4C4P8fIS+V8qCJmVNSDU44UZBc+D+J6ZTgW8JeOHUIj\n"
// "Bh++XDg3gwat7pIWQ8AU5R7h+fpBI9n3dadyIsMHGwSogHY9Gw7di2RVtSFajEth\n"
// "rvrq0JbzpwoYedMh84sJ2qI/DGKW9/Is9+O52fR+3z3dY3gNRDPQ5675BQ5CQW9I\n"
// "AJgLOqzD8Q0qrXYi7HaEqzNx6p7RDTuhFgvTd+vS5d5+28Z5fm2umnq+GKHF8W5P\n"
// "ylp2Js119FTVO7brusAMKPe5emc7tC2ov8OFFemQvfHR41PLryap2VD81IOgmt/J\n"
// "kX/j/y5KGux5HZ3lxXqdJbKcAq4NKYQT0mCkRD4l6szaCEJ+k0SiM9DdTcBDefhR\n"
// "9q+pCOyMh7d8QjQ1075mF7T+PGkZQUW1DUjEfrZhICnKgq+iEoUmM0Ee5WtRqcnu\n"
// "5BTGQ2mSfc6rV+Vr+eYXqcg7Nxb3vFXYSTod1UhefonVqwdmyJ2sC79zp36Tbo2+\n"
// "65NW2WJK7KzPUyOJU0U9bcu0utvDOvGWmG+aHbymJgcoFzvZmlXqMXn97pSFn4jV\n"
// "y3SLRgJXOw1QLXL2Y5abcuoBVr4gCOxxk2vBeVxOMRXNqSWZOFIF1bu/PxuDA+Sa\n"
// "hEi44aHbPXt9opdssz/hdGfd8Wo7vEJrbg7c6zR6C/Akav1Rzy9oohIdgOw=\n"
// "-----END CERTIFICATE-----\n");
        Option oCa;
        oCa.push_back("ca");
        oCa.push_back(caVal);
        state->options.add_item(oCa);

//         std::string certVal = std::string("-----BEGIN CERTIFICATE-----\n"
// "MIIFFDCCAvygAwIBAgIBAjANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJLRzEL\n"
// "MAkGA1UECBMCTkExEDAOBgNVBAcTB0JJU0hLRUsxFTATBgNVBAoTDE9wZW5WUE4t\n"
// "VEVTVDEhMB8GCSqGSIb3DQEJARYSbWVAbXlob3N0Lm15ZG9tYWluMB4XDTE0MTAy\n"
// "MjIxNTk1M1oXDTI0MTAxOTIxNTk1M1owajELMAkGA1UEBhMCS0cxCzAJBgNVBAgT\n"
// "Ak5BMRUwEwYDVQQKEwxPcGVuVlBOLVRFU1QxFDASBgNVBAMTC1Rlc3QtQ2xpZW50\n"
// "MSEwHwYJKoZIhvcNAQkBFhJtZUBteWhvc3QubXlkb21haW4wggEiMA0GCSqGSIb3\n"
// "DQEBAQUAA4IBDwAwggEKAoIBAQDsZY/pEsIaW+ZWKgipgjotRHijADuwn+cnEECT\n"
// "7/HMPqCqBKKAGxOp5v6B1nCQqNjU3jDYNQDSvmLwSNr8FY3Exm0LmfErgwAK0yoj\n"
// "C+XN+TXfQ2EVcq2VmPZzIUFeoN1HJ6DVmtRBqBwdVyBxF4/3KJ4+B87s1Q5CTx50\n"
// "R45HndIUKCcsFBD10Za1k3SE7/kE3o1Kb993q+rRWNNE/loEAf8Gepf3/eNXSOHw\n"
// "30ATn2YjWuNVVD1UOe4A+RLx0t90LrrX8I3G3RhYHJMiC3X6qNbgtS8tudT+uU+G\n"
// "4nVIFmD7P8m0MEIp+zuzK7lZgWpG80WDv/3VGv83DG9b/WHxAgMBAAGjgcgwgcUw\n"
// "CQYDVR0TBAIwADAdBgNVHQ4EFgQU0rQ2D7H83aXqKvfHI4n64/p6RB0wgZgGA1Ud\n"
// "IwSBkDCBjYAUK0DlyX319JY46S/jL9lAZMmOBZuhaqRoMGYxCzAJBgNVBAYTAktH\n"
// "MQswCQYDVQQIEwJOQTEQMA4GA1UEBxMHQklTSEtFSzEVMBMGA1UEChMMT3BlblZQ\n"
// "Ti1URVNUMSEwHwYJKoZIhvcNAQkBFhJtZUBteWhvc3QubXlkb21haW6CCQChTt76\n"
// "kPKugTANBgkqhkiG9w0BAQsFAAOCAgEAf+D+hKfs32KlzTzB5kKxMRLwudqnnj+9\n"
// "llK2/FV0ZD7k/36q9z4GGF9zhfjI4GcbTZfKBdA3BzNkm+Z4dxSaVbsqrMN/yRUI\n"
// "g1zIwmHTcUwFCyvLo4dtoDLtsLMnl0pVjQEqMFZoq/LaXBBzyaoKnEtMoFtRbgp+\n"
// "bFOAsADhHppMCjeeIIm8xeV5WLdF/9PEof3ZeD1FFnTfgkQdHYFQWrkyTOJPPw46\n"
// "ZVpkgzspMcSZiLzFhDnyGRLhZtDq+3Wx0ie+kVmjKwnVXL9GjtZn1gvs2qvwgBmH\n"
// "ZAepd7FeDOLFHWqsXSPzMHU2TsrDTrBNjCzOUmFj3tX17+8KayMlJjw68sPCFhk/\n"
// "qTK6aPnJEjw+xh//m070kLBj9dEzADBa6CT6NUSbaoDzpsx7PHNfUMQwcdh0kCcK\n"
// "AU6lXrH42sJhgRGuKaOP+n5MTmKxAN6S449qLtrZOF1rfA3kAarIxm2LzcDIbuRX\n"
// "IYr2RjDZrVGhh5amU8kexrvD61X+jNZc1cbzyrBg0tQqH4iU00wa2gyU/sFdDSrb\n"
// "mSld9t0WxMhNdJ6A2dCq7XvjMORH2PUVwXG4xv3u/J6yX7W3ku3/yjf2x4K0VBOb\n"
// "g82Hi35k9i5UOiKxxcH0pSVTmk2oD+c1S4nfGYNmZNnb0WErJBsdRET7STCHt0kj\n"
// "CAKK4CXz9EM=\n"
// "-----END CERTIFICATE-----\n");
        Option oCert;
        oCert.push_back("cert");
        oCert.push_back(certVal);
        state->options.add_item(oCert);

//         std::string keyVal = std::string("-----BEGIN PRIVATE KEY-----\n"
// "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDsZY/pEsIaW+ZW\n"
// "KgipgjotRHijADuwn+cnEECT7/HMPqCqBKKAGxOp5v6B1nCQqNjU3jDYNQDSvmLw\n"
// "SNr8FY3Exm0LmfErgwAK0yojC+XN+TXfQ2EVcq2VmPZzIUFeoN1HJ6DVmtRBqBwd\n"
// "VyBxF4/3KJ4+B87s1Q5CTx50R45HndIUKCcsFBD10Za1k3SE7/kE3o1Kb993q+rR\n"
// "WNNE/loEAf8Gepf3/eNXSOHw30ATn2YjWuNVVD1UOe4A+RLx0t90LrrX8I3G3RhY\n"
// "HJMiC3X6qNbgtS8tudT+uU+G4nVIFmD7P8m0MEIp+zuzK7lZgWpG80WDv/3VGv83\n"
// "DG9b/WHxAgMBAAECggEBAIOdaCpUD02trOh8LqZxowJhBOl7z7/ex0uweMPk67LT\n"
// "i5AdVHwOlzwZJ8oSIknoOBEMRBWcLQEojt1JMuL2/R95emzjIKshHHzqZKNulFvB\n"
// "TIUpdnwChTKtH0mqUkLlPU3Ienty4IpNlpmfUKimfbkWHERdBJBHbtDsTABhdo3X\n"
// "9pCF/yRKqJS2Fy/Mkl3gv1y/NB1OL4Jhl7vQbf+kmgfQN2qdOVe2BOKQ8NlPUDmE\n"
// "/1XNIDaE3s6uvUaoFfwowzsCCwN2/8QrRMMKkjvV+lEVtNmQdYxj5Xj5IwS0vkK0\n"
// "6icsngW87cpZxxc1zsRWcSTloy5ohub4FgKhlolmigECgYEA+cBlxzLvaMzMlBQY\n"
// "kCac9KQMvVL+DIFHlZA5i5L/9pRVp4JJwj3GUoehFJoFhsxnKr8HZyLwBKlCmUVm\n"
// "VxnshRWiAU18emUmeAtSGawlAS3QXhikVZDdd/L20YusLT+DXV81wlKR97/r9+17\n"
// "klQOLkSdPm9wcMDOWMNHX8bUg8kCgYEA8k+hQv6+TR/+Beao2IIctFtw/EauaJiJ\n"
// "wW5ql1cpCLPMAOQUvjs0Km3zqctfBF8mUjdkcyJ4uhL9FZtfywY22EtRIXOJ/8VR\n"
// "we65mVo6RLR8YVM54sihanuFOnlyF9LIBWB+9pUfh1/Y7DSebh7W73uxhAxQhi3Y\n"
// "QwfIQIFd8OkCgYBalH4VXhLYhpaYCiXSej6ot6rrK2N6c5Tb2MAWMA1nh+r84tMP\n"
// "gMoh+pDgYPAqMI4mQbxUmqZEeoLuBe6VHpDav7rPECRaW781AJ4ZM4cEQ3Jz/inz\n"
// "4qOAMn10CF081/Ez9ykPPlU0bsYNWHNd4eB2xWnmUBKOwk7UgJatVPaUiQKBgQCI\n"
// "f18CVGpzG9CHFnaK8FCnMNOm6VIaTcNcGY0mD81nv5Dt943P054BQMsAHTY7SjZW\n"
// "HioRyZtkhonXAB2oSqnekh7zzxgv4sG5k3ct8evdBCcE1FNJc2eqikZ0uDETRoOy\n"
// "s7cRxNNr+QxDkyikM+80HOPU1PMPgwfOSrX90GJQ8QKBgEBKohGMV/sNa4t14Iau\n"
// "qO8aagoqh/68K9GFXljsl3/iCSa964HIEREtW09Qz1w3dotEgp2w8bsDa+OwWrLy\n"
// "0SY7T5jRViM3cDWRlUBLrGGiL0FiwsfqiRiji60y19erJgrgyGVIb1kIgIBRkgFM\n"
// "2MMweASzTmZcri4PA/5C0HYb\n"
// "-----END PRIVATE KEY-----\n");
        Option oKey;
        oKey.push_back("key");
        oKey.push_back(keyVal);
        state->options.add_item(oKey);
    }

    enum ClockTickAction {
        CT_UNDEF,
        CT_STOP,
        CT_RECONNECT,
        CT_PAUSE,
        CT_RESUME,
        CT_STATS,
    };

    void set_clock_tick_action(const ClockTickAction action)
    {
        clock_tick_action = action;
    }

    void print_stats()
    {
        const int n = stats_n();
        std::vector<long long> stats = stats_bundle();

        std::cout << "STATS:" << std::endl;
        for (int i = 0; i < n; ++i)
        {
            const long long value = stats[i];
            if (value)
                std::cout << "  " << stats_name(i) << " : " << value << std::endl;
        }
    }

private:
    std::mutex log_mutex;
    volatile ClockTickAction clock_tick_action = CT_UNDEF;
    std::string remote_override_cmd;

    virtual void event(const ClientAPI::Event& ev) override
    {
    }

    virtual void log(const ClientAPI::LogInfo& log) override
    {
        std::lock_guard<std::mutex> lock(log_mutex);
        std::cout << date_time() << ' ' << log.text << std::flush;
    }

    virtual void clock_tick() override
    {
        const ClockTickAction action = clock_tick_action;
        clock_tick_action = CT_UNDEF;

        switch (action)
        {
        case CT_STOP:
            std::cout << "signal: CT_STOP" << std::endl;
            stop();
            break;
        case CT_RECONNECT:
            std::cout << "signal: CT_RECONNECT" << std::endl;
            reconnect(0);
            break;
        case CT_PAUSE:
            std::cout << "signal: CT_PAUSE" << std::endl;
            pause("clock-tick pause");
            break;
        case CT_RESUME:
            std::cout << "signal: CT_RESUME" << std::endl;
            resume();
            break;
        case CT_STATS:
            std::cout << "signal: CT_STATS" << std::endl;
            print_stats();
            break;
        default:
            break;
        }
    }

    virtual void external_pki_cert_request(ClientAPI::ExternalPKICertRequest& certreq) override
    {
    }

    virtual void external_pki_sign_request(ClientAPI::ExternalPKISignRequest& signreq) override
    {
    }

    virtual bool remote_override_enabled() override
    {
        return false;
    }

    virtual void remote_override(ClientAPI::RemoteOverride& ro) override
    {
        RedirectPipe::InOut pio;
        Argv argv;
        argv.emplace_back(remote_override_cmd);
        OPENVPN_LOG("argv: " + argv.to_string());
        const int status = system_cmd(remote_override_cmd,
                                      argv,
                                      nullptr,
                                      pio,
                                      RedirectPipe::IGNORE_ERR,
                                      nullptr);
        if (!status)
        {
            const std::string out = string::first_line(pio.out);
            OPENVPN_LOG("REMOTE OVERRIDE: " + out);
            auto svec = string::split(out, ',');
            if (svec.size() == 4)
            {
                ro.host = svec[0];
                ro.ip = svec[1];
                ro.port = svec[2];
                ro.proto = svec[3];
            }
            else
                ro.error = "cannot parse remote-override, expecting host,ip,port,proto (at least one or both of host and ip must be defined)";
        }
        else
            ro.error = "status=" + std::to_string(status);
    }

    virtual bool pause_on_connection_timeout() override
    {
        return false;
    }

    // // RNG callback
    // static int rng_callback(void *arg, unsigned char *data, size_t len)
    // {
    //     Client *self = (Client *)arg;
    //     if (!self->rng)
    //     {
    //         self->rng.reset(new SSLLib::RandomAPI(false));
    //         self->rng->assert_crypto();
    //     }
    //     return self->rng->rand_bytes_noexcept(data, len) ? 0 : -1; // using -1 as a general-purpose mbed TLS error code
    // }

};

int main(int argc, char *argv[])
{
    Client client;
    client.connect();
}
