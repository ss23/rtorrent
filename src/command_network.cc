// rTorrent - BitTorrent client
// Copyright (C) 2005-2011, Jari Sundell
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
// In addition, as a special exception, the copyright holders give
// permission to link the code of portions of this program with the
// OpenSSL library under certain conditions as described in each
// individual source file, and distribute linked combinations
// including the two.
//
// You must obey the GNU General Public License in all respects for
// all of the code used other than OpenSSL.  If you modify file(s)
// with this exception, you may extend this exception to your version
// of the file(s), but you are not obligated to do so.  If you do not
// wish to do so, delete this exception statement from your version.
// If you delete this exception statement from all source files in the
// program, then also delete it here.
//
// Contact:  Jari Sundell <jaris@ifi.uio.no>
//
//           Skomakerveien 33
//           3185 Skoppum, NORWAY

#include "config.h"

#include <functional>
#include <cstdio>
#include <unistd.h>
#include <rak/address_info.h>
#include <rak/path.h>
#include <torrent/connection_manager.h>
#include <torrent/tracker.h>
#include <torrent/tracker_list.h>
#include <torrent/torrent.h>
#include <torrent/rate.h>
#include <torrent/data/file_manager.h>
#include <torrent/download/resource_manager.h>
#include <torrent/net/bind_manager.h>
#include <torrent/net/socket_address.h>
#include <torrent/utils/log.h>
#include <torrent/utils/option_strings.h>

#include "core/download.h"
#include "core/manager.h"
#include "rpc/scgi.h"
#include "ui/root.h"
#include "rpc/parse.h"
#include "rpc/parse_commands.h"
#include "rpc/parse_options.h"

#include "globals.h"
#include "control.h"
#include "command_helpers.h"

torrent::Object
apply_encryption(const torrent::Object::list_type& args) {
  uint32_t options_mask = torrent::ConnectionManager::encryption_none;

  for (torrent::Object::list_const_iterator itr = args.begin(), last = args.end(); itr != last; itr++) {
    uint32_t opt = torrent::option_find_string(torrent::OPTION_ENCRYPTION, itr->as_string().c_str());

    if (opt == torrent::ConnectionManager::encryption_none)
      options_mask = torrent::ConnectionManager::encryption_none;
    else
      options_mask |= opt;
  }

  torrent::connection_manager()->set_encryption_options(options_mask);

  return torrent::Object();
}

torrent::Object
apply_tos(const torrent::Object::string_type& arg) {
  rpc::command_base::value_type value;

  if (!rpc::parse_whole_value_nothrow(arg.c_str(), &value, 16, 1))
    value = torrent::option_find_string(torrent::OPTION_IP_TOS, arg.c_str());

  torrent::connection_manager()->set_priority(value);

  return torrent::Object();
}

torrent::Object apply_encoding_list(const std::string& arg) { torrent::encoding_list()->push_back(arg); return torrent::Object(); }

torrent::File*
xmlrpc_find_file(core::Download* download, uint32_t index) {
  if (index >= download->file_list()->size_files())
    return NULL;

  return (*download->file_list())[index];
}

// Ergh... time to update the Tracker API to allow proper ptrs.
torrent::Tracker*
xmlrpc_find_tracker(core::Download* download, uint32_t index) {
  if (index >= download->tracker_list()->size())
    return NULL;

  return download->tracker_list()->at(index);
}

torrent::Peer*
xmlrpc_find_peer(core::Download* download, const torrent::HashString& hash) {
  torrent::ConnectionList::iterator itr = download->connection_list()->find(hash.c_str());

  if (itr == download->connection_list()->end())
    return NULL;

  return *itr;
}

void
initialize_xmlrpc() {
  rpc::xmlrpc.initialize();
  rpc::xmlrpc.slot_find_download() = std::bind(&core::DownloadList::find_hex_ptr, control->core()->download_list(), std::placeholders::_1);
  rpc::xmlrpc.slot_find_file() = std::bind(&xmlrpc_find_file, std::placeholders::_1, std::placeholders::_2);
  rpc::xmlrpc.slot_find_tracker() = std::bind(&xmlrpc_find_tracker, std::placeholders::_1, std::placeholders::_2);
  rpc::xmlrpc.slot_find_peer() = std::bind(&xmlrpc_find_peer, std::placeholders::_1, std::placeholders::_2);

  unsigned int count = 0;

  for (rpc::CommandMap::const_iterator itr = rpc::commands.begin(), last = rpc::commands.end(); itr != last; itr++, count++) {
    if (!(itr->second.m_flags & rpc::CommandMap::flag_public_xmlrpc))
      continue;

    rpc::xmlrpc.insert_command(itr->first, itr->second.m_parm, itr->second.m_doc);
  }

  lt_log_print(torrent::LOG_RPC_EVENTS, "XMLRPC initialized with %u functions.", count);
}

torrent::Object
apply_scgi(const std::string& arg, int type) {
  if (worker_thread->scgi() != NULL)
    throw torrent::input_error("SCGI already enabled.");

  if (!rpc::xmlrpc.is_valid())
    initialize_xmlrpc();

  rpc::SCgi* scgi = new rpc::SCgi;

  rak::address_info* ai = NULL;
  rak::socket_address sa;
  rak::socket_address* saPtr;

  try {
    int port, err;
    char dummy;
    char address[1024];
    std::string path;

    switch (type) {
    case 1:
      if (std::sscanf(arg.c_str(), ":%i%c", &port, &dummy) == 1) {
        sa.sa_inet()->clear();
        saPtr = &sa;

        lt_log_print(torrent::LOG_RPC_EVENTS,
                     "The SCGI socket has not been bound to any address and likely poses a security risk.");

      } else if (std::sscanf(arg.c_str(), "%1023[^:]:%i%c", address, &port, &dummy) == 2 ||
                 std::sscanf(arg.c_str(), "[%64[^]]]:%i%c", address, &port, &dummy) == 2) { // [xx::xx]:port format
        if ((err = rak::address_info::get_address_info(address,PF_UNSPEC, SOCK_STREAM, &ai)) != 0)
          throw torrent::input_error("Could not bind address: " + std::string(rak::address_info::strerror(err)) + ".");

        saPtr = ai->address();

        lt_log_print(torrent::LOG_RPC_EVENTS,
                     "The SCGI socket is bound to a specific network device yet may still pose a security risk, consider using 'scgi_local'.");

      } else {
        throw torrent::input_error("Could not parse address.");
      }

      if (port <= 0 || port >= (1 << 16))
        throw torrent::input_error("Invalid port number.");

      saPtr->set_port(port);
      scgi->open_port(saPtr, saPtr->length(), rpc::call_command_value("network.scgi.dont_route"));

      break;

    case 2:
    default:
      path = rak::path_expand(arg);

      unlink(path.c_str());
      scgi->open_named(path);
      break;
    }

    if (ai != NULL) rak::address_info::free_address_info(ai);

  } catch (torrent::local_error& e) {
    if (ai != NULL) rak::address_info::free_address_info(ai);

    delete scgi;
    throw torrent::input_error(e.what());
  }

  worker_thread->set_scgi(scgi);
  return torrent::Object();
}

torrent::Object
apply_xmlrpc_dialect(const std::string& arg) {
  int value;

  if (arg == "i8")
    value = rpc::XmlRpc::dialect_i8;
  else if (arg == "apache")
    value = rpc::XmlRpc::dialect_apache;
  else if (arg == "generic")
    value = rpc::XmlRpc::dialect_generic;
  else
    value = -1;

  rpc::xmlrpc.set_dialect(value);
  return torrent::Object();
}

typedef std::function<void (const sockaddr*)> sockaddr_func;

static void
convert_string_to_sockaddr(const std::string& addr, sockaddr_func lambda) {
  int err;
  rak::address_info* ai;

  if ((err = rak::address_info::get_address_info(addr.c_str(), PF_INET, SOCK_STREAM, &ai)) != 0 &&
      (err = rak::address_info::get_address_info(addr.c_str(), PF_INET6, SOCK_STREAM, &ai)) != 0)
    throw torrent::input_error("Could not set bind address: " + std::string(rak::address_info::strerror(err)) + ".");
  
  try {
    lambda(ai->address()->c_sockaddr());

    rak::address_info::free_address_info(ai);

  } catch (torrent::input_error& e) {
    rak::address_info::free_address_info(ai);
    throw e;
  }
}

static torrent::Object
bind_set_address(const torrent::Object::list_type& args) {
  if (args.size() != 1)
    throw torrent::input_error("Wrong argument count.");

  auto args_itr = args.begin();
  auto bind_address = args_itr->as_string();

  torrent::bind()->clear();

  convert_string_to_sockaddr(bind_address, [] (const sockaddr* sa) { torrent::bind()->add_bind(sa, 0); });

  return torrent::Object();
}

static torrent::Object
bind_list() {
  auto result = torrent::Object::create_list();

  for (auto& itr : *torrent::bind()) {
    auto entry = torrent::Object::create_list();

    entry.insert_back(itr.name);
    entry.insert_back(torrent::sa_addr_str(itr.address.get()));
    entry.insert_back(itr.listen_port_first);
    entry.insert_back(itr.listen_port_last);
    entry.insert_back(itr.priority);
    entry.insert_back(rpc::parse_option_print_flags(itr.flags, std::bind(&torrent::option_to_string, torrent::OPTION_BIND, std::placeholders::_1, "invalid")));

    result.insert_back(entry);
  }

  return result;
}

static torrent::Object
network_port_range() {
  char buf[12];

  snprintf(buf, 12, "%" PRIu16 "-%" PRIu16, torrent::bind()->listen_port_first(), torrent::bind()->listen_port_last());
  return buf;
}

static void
network_port_range_set(const std::string& arg) {
  uint16_t port_first;
  uint16_t port_last;

  if (std::sscanf(arg.c_str(), "%" PRIu16 "-%" PRIu16, &port_first, &port_last) != 2)
    throw torrent::input_error("Invalid port_range argument.");

  torrent::bind()->set_listen_port_range(port_first, port_last, 0);
}

void
initialize_command_network() {
  auto bm = torrent::bind();
  auto cm = torrent::connection_manager();
  auto fm = torrent::file_manager();
  auto hs = control->core()->http_stack();

  CMD2_ANY_STRING  ("encoding.add", std::bind(&apply_encoding_list, std::placeholders::_2));

  CMD2_VAR_BOOL    ("protocol.pex",            true);
  CMD2_ANY_LIST    ("protocol.encryption.set", std::bind(&apply_encryption, std::placeholders::_2));

  CMD2_VAR_STRING  ("protocol.connection.leech", "leech");
  CMD2_VAR_STRING  ("protocol.connection.seed",  "seed");

  CMD2_VAR_STRING  ("protocol.choke_heuristics.up.leech", "upload_leech");
  CMD2_VAR_STRING  ("protocol.choke_heuristics.up.seed",  "upload_leech");
  CMD2_VAR_STRING  ("protocol.choke_heuristics.down.leech", "download_leech");
  CMD2_VAR_STRING  ("protocol.choke_heuristics.down.seed",  "download_leech");

  CMD2_ANY         ("network.http.cacert",                std::bind(&core::CurlStack::http_cacert, hs));
  CMD2_ANY_STRING_V("network.http.cacert.set",            std::bind(&core::CurlStack::set_http_cacert, hs, std::placeholders::_2));
  CMD2_ANY         ("network.http.capath",                std::bind(&core::CurlStack::http_capath, hs));
  CMD2_ANY_STRING_V("network.http.capath.set",            std::bind(&core::CurlStack::set_http_capath, hs, std::placeholders::_2));
  CMD2_ANY         ("network.http.dns_cache_timeout",     std::bind(&core::CurlStack::dns_timeout, hs));
  CMD2_ANY_VALUE_V ("network.http.dns_cache_timeout.set", std::bind(&core::CurlStack::set_dns_timeout, hs, std::placeholders::_2));
  CMD2_ANY         ("network.http.current_open",          std::bind(&core::CurlStack::active, hs));
  CMD2_ANY         ("network.http.max_open",              std::bind(&core::CurlStack::max_active, hs));
  CMD2_ANY_VALUE_V ("network.http.max_open.set",          std::bind(&core::CurlStack::set_max_active, hs, std::placeholders::_2));
  CMD2_ANY         ("network.http.proxy_address",         std::bind(&core::CurlStack::http_proxy, hs));
  CMD2_ANY_STRING_V("network.http.proxy_address.set",     std::bind(&core::CurlStack::set_http_proxy, hs, std::placeholders::_2));
  CMD2_ANY         ("network.http.ssl_verify_host",       std::bind(&core::CurlStack::ssl_verify_host, hs));
  CMD2_ANY_VALUE_V ("network.http.ssl_verify_host.set",   std::bind(&core::CurlStack::set_ssl_verify_host, hs, std::placeholders::_2));
  CMD2_ANY         ("network.http.ssl_verify_peer",       std::bind(&core::CurlStack::ssl_verify_peer, hs));
  CMD2_ANY_VALUE_V ("network.http.ssl_verify_peer.set",   std::bind(&core::CurlStack::set_ssl_verify_peer, hs, std::placeholders::_2));

  CMD2_ANY         ("network.send_buffer.size",           std::bind(&torrent::ConnectionManager::send_buffer_size, cm));
  CMD2_ANY_VALUE_V ("network.send_buffer.size.set",       std::bind(&torrent::ConnectionManager::set_send_buffer_size, cm, std::placeholders::_2));
  CMD2_ANY         ("network.receive_buffer.size",        std::bind(&torrent::ConnectionManager::receive_buffer_size, cm));
  CMD2_ANY_VALUE_V ("network.receive_buffer.size.set",    std::bind(&torrent::ConnectionManager::set_receive_buffer_size, cm, std::placeholders::_2));
  CMD2_ANY_STRING  ("network.tos.set",                    std::bind(&apply_tos, std::placeholders::_2));

  CMD2_ANY         ("network.bind_address",          std::bind(&core::Manager::bind_address, control->core()));
  CMD2_ANY_STRING_V("network.bind_address.set",      std::bind(&core::Manager::set_bind_address, control->core(), std::placeholders::_2));
  CMD2_ANY         ("network.local_address",         std::bind(&core::Manager::local_address, control->core()));
  CMD2_ANY_STRING_V("network.local_address.set",     std::bind(&core::Manager::set_local_address, control->core(), std::placeholders::_2));
  CMD2_ANY         ("network.proxy_address",         std::bind(&core::Manager::proxy_address, control->core()));
  CMD2_ANY_STRING_V("network.proxy_address.set",     std::bind(&core::Manager::set_proxy_address, control->core(), std::placeholders::_2));

  CMD2_ANY_LIST    ("network.bind.set_address",      std::bind(&bind_set_address, std::placeholders::_2));

  CMD2_ANY         ("network.bind",                  std::bind(&bind_list));
  CMD2_ANY_V       ("network.bind.clear",            std::bind(&torrent::bind_manager::clear, bm));

  //CMD2_ANY_LIST    ("network.bind.add",              std::bind(&bind_add, std::placeholders::_2));

  //CMD2_ANY_LIST    ("network.bind.ipv4.set",         std::bind(&torrent::BindManager::clear, bind));

  CMD2_ANY_V       ("network.listen.open",           std::bind(&torrent::bind_manager::listen_open, bm));
  CMD2_ANY_V       ("network.listen.close",          std::bind(&torrent::bind_manager::listen_close, bm));
  CMD2_ANY         ("network.listen.is_open",        std::bind(&torrent::bind_manager::is_listen_open, bm));
  CMD2_ANY         ("network.listen.backlog",        std::bind(&torrent::bind_manager::listen_backlog, bm));
  CMD2_ANY_VALUE_V ("network.listen.backlog.set",    std::bind(&torrent::bind_manager::set_listen_backlog, bm, std::placeholders::_2));

  CMD2_ANY         ("network.port",                  std::bind(&torrent::bind_manager::listen_port, bm));
  CMD2_ANY         ("network.port.first",            std::bind(&torrent::bind_manager::listen_port_first, bm));
  CMD2_ANY         ("network.port.last",             std::bind(&torrent::bind_manager::listen_port_last, bm));
  CMD2_ANY         ("network.port.randomize",        std::bind(&torrent::bind_manager::is_port_randomize, bm));
  CMD2_ANY_VALUE_V ("network.port.randomize.set",    std::bind(&torrent::bind_manager::set_port_randomize, bm, std::placeholders::_2));
  CMD2_ANY         ("network.port.range",            std::bind(&network_port_range));
  CMD2_ANY_STRING_V("network.port.range.set",        std::bind(&network_port_range_set, std::placeholders::_2));

  CMD2_ANY         ("network.max_open_files",        std::bind(&torrent::FileManager::max_open_files, fm));
  CMD2_ANY_VALUE_V ("network.max_open_files.set",    std::bind(&torrent::FileManager::set_max_open_files, fm, std::placeholders::_2));
  CMD2_ANY         ("network.open_sockets",          std::bind(&torrent::ConnectionManager::size, cm));
  CMD2_ANY         ("network.max_open_sockets",      std::bind(&torrent::ConnectionManager::max_size, cm));
  CMD2_ANY_VALUE_V ("network.max_open_sockets.set",  std::bind(&torrent::ConnectionManager::set_max_size, cm, std::placeholders::_2));

  CMD2_ANY_STRING  ("network.scgi.open_port",        std::bind(&apply_scgi, std::placeholders::_2, 1));
  CMD2_ANY_STRING  ("network.scgi.open_local",       std::bind(&apply_scgi, std::placeholders::_2, 2));
  CMD2_VAR_BOOL    ("network.scgi.dont_route",       false);

  CMD2_ANY_STRING  ("network.xmlrpc.dialect.set",    std::bind(&apply_xmlrpc_dialect, std::placeholders::_2));
  CMD2_ANY         ("network.xmlrpc.size_limit",     std::bind(&rpc::XmlRpc::size_limit));
  CMD2_ANY_VALUE_V ("network.xmlrpc.size_limit.set", std::bind(&rpc::XmlRpc::set_size_limit, std::placeholders::_2));
}
