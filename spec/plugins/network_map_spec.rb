# frozen_string_literal: true

require 'spec_helper'
require Metasploit::Framework.root.join('plugins/network_map.rb').to_path
require 'timeout'

RSpec.describe Msf::Plugin::NetworkMapLive::LiveServer do
  subject(:server) { described_class.new(framework, plugin) }

  let(:framework) { instance_double(Msf::Framework, db: double(active: false), jobs: {}) }
  let(:plugin) do
    instance_double(
      Msf::Plugin::NetworkMapLive,
      tap_status: nil,
      tap_warning: nil,
      reset_console_snapshot: nil,
      console_snapshot: { last_command: 'set Password secret', tail: ['secret output'] }
    )
  end
  let(:listener) { instance_double(TCPServer, addr: [Socket::AF_INET, 4646, '0.0.0.0', '0.0.0.0'], close: nil) }

  before do
    allow(TCPServer).to receive(:new).and_return(listener)
    allow(server).to receive(:thread_named)
  end

  after { server.stop }

  it 'pins shared listeners to the configured browser authority and origin' do
    server.start(host: '0.0.0.0', origin: 'http://192.0.2.10:4646', password: 'correct horse battery staple')

    expect(server.send(:host_allowed?, 'host' => '192.0.2.10:4646')).to be(true)
    expect(server.send(:origin_allowed?, 'origin' => 'http://192.0.2.10:4646')).to be(true)
    expect(server.send(:host_allowed?, 'host' => 'attacker.example:4646')).to be(false)
    expect(server.send(:origin_allowed?, 'origin' => 'http://attacker.example:9000')).to be(false)
    expect(server.send(:origin_allowed?, 'origin' => 'http://192.0.2.10:9000')).to be(false)
  end

  it 'normalizes default ports and hostname case like browser Origin values' do
    server.start(host: '0.0.0.0', origin: 'https://MAP.example:443', password: 'correct horse battery staple')

    expect(server.url).to eq('https://map.example/')
    expect(server.send(:host_allowed?, 'host' => 'map.example')).to be(true)
    expect(server.send(:origin_allowed?, 'origin' => 'https://map.example')).to be(true)
  end

  it 'prints and authorizes a valid IPv6 loopback authority' do
    server.start(host: '::1', password: 'correct horse battery staple')

    expect(server.url).to eq('http://[::1]:4646/')
    expect(server.send(:host_allowed?, 'host' => '[::1]:4646')).to be(true)
    expect(server.send(:origin_allowed?, 'origin' => 'http://[::1]:4646')).to be(true)
  end

  it 'rejects origins containing paths or credentials' do
    %w[http://map.example/path http://user:pass@map.example].each do |origin|
      expect { server.start(origin: origin) }.to raise_error(ArgumentError)
      expect(server).not_to be_running
    end
  end

  it 'disconnects existing viewers when the password rotates' do
    socket = instance_double(TCPSocket, close: nil)
    server.instance_variable_get(:@clients) << {
      sock: socket, outbox: [], outbox_lock: Mutex.new,
      outbox_condvar: ConditionVariable.new, closed: false
    }

    server.set_password('new password')

    expect(socket).to have_received(:close)
    expect(server.client_count).to eq(0)
  end

  it 'does not retain the plaintext password for later status output' do
    server.start(password: 'not retained')

    expect(server.status).not_to include(:password)
  end

  it 'does not include arbitrary console output by default' do
    server.start(password: 'not retained')

    expect(server.send(:live_msf_details)).to eq(jobs: [])
    expect(plugin).not_to have_received(:console_snapshot)
  end

  it 'requires an explicit opt-in to include console output' do
    server.start(password: 'not retained', console_feed: true)

    expect(server.send(:live_msf_details)).to include(last_command: 'set Password secret', console_tail: ['secret output'])
    expect(server.status[:console_feed]).to be(true)
  end
end

RSpec.describe Msf::Plugin::NetworkMapLive::LiveServer, 'socket boundary' do
  subject(:server) { described_class.new(framework, plugin) }

  let(:database) { double(active: false) }
  let(:framework) { instance_double(Msf::Framework, db: database, jobs: {}) }
  let(:plugin) do
    instance_double(
      Msf::Plugin::NetworkMapLive,
      console_activity_version: 0,
      console_snapshot: { last_command: nil, tail: [] },
      reset_console_snapshot: nil,
      tap_status: nil,
      tap_warning: nil
    )
  end
  let(:password) { 'correct horse battery staple' }
  let(:authority) { "127.0.0.1:#{server.port}" }
  let(:authorization) { "Basic #{Base64.strict_encode64(":#{password}")}" }

  before { server.start(host: '127.0.0.1', port: 0, password: password) }
  after { server.stop }

  def request(raw_request)
    socket = TCPSocket.new('127.0.0.1', server.port)
    socket.write(raw_request)
    socket.close_write
    Timeout.timeout(2) { socket.read }
  ensure
    socket&.close
  end

  it 'rejects an unexpected Host before challenging for credentials' do
    response = request("GET /health HTTP/1.1\r\nHost: attacker.example\r\n\r\n")

    expect(response).to start_with('HTTP/1.1 403 Forbidden')
    expect(response).not_to include('WWW-Authenticate')
  end

  it 'requires authentication and gives HEAD requests no response body' do
    challenge = request("GET /health HTTP/1.1\r\nHost: #{authority}\r\n\r\n")
    head = request("HEAD /health HTTP/1.1\r\nHost: #{authority}\r\nAuthorization: #{authorization}\r\n\r\n")

    expect(challenge).to start_with('HTTP/1.1 401 Unauthorized')
    expect(head).to match(%r{\AHTTP/1\.1 200 OK.*Content-Length: 3\r\n.*\r\n\r\n\z}m)
  end

  it 'rejects methods and malformed websocket upgrades' do
    post = request("POST /health HTTP/1.1\r\nHost: #{authority}\r\nAuthorization: #{authorization}\r\n\r\n")
    websocket = request("GET /ws HTTP/1.1\r\nHost: #{authority}\r\nAuthorization: #{authorization}\r\nUpgrade: websocket\r\n\r\n")

    expect(post).to start_with('HTTP/1.1 405 Method Not Allowed')
    expect(websocket).to start_with('HTTP/1.1 400 Bad Request')
  end

  it 'accepts a complete websocket upgrade from the configured origin' do
    key = Base64.strict_encode64('0123456789abcdef')
    websocket = request(
      "GET /ws HTTP/1.1\r\nHost: #{authority}\r\nAuthorization: #{authorization}\r\n" \
      "Connection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nOrigin: #{server.url.delete_suffix('/')}\r\n" \
      "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: #{key}\r\n\r\n"
    )

    expect(websocket).to start_with('HTTP/1.1 101 Switching Protocols')
  end

  it 'caps unauthenticated HTTP headers' do
    oversized = "GET /health HTTP/1.1\r\nHost: #{authority}\r\nX-Fill: #{'a' * (described_class::MAX_HTTP_HEADER_LINE_BYTES + 1)}\r\n\r\n"

    expect(request(oversized)).to start_with('HTTP/1.1 431 Request Header Fields Too Large')
  end

  it 'expires incomplete HTTP headers' do
    stub_const('Msf::Plugin::NetworkMapLive::LiveServer::HTTP_HEADER_TIMEOUT', 0.05)
    socket = TCPSocket.new('127.0.0.1', server.port)
    socket.write("GET /health HTTP/1.1\r\n")

    expect(Timeout.timeout(1) { socket.read }).to eq('')
  ensure
    socket&.close
  end

  it 'requires masked client frames and caps their payload length' do
    unmasked_reader, unmasked_writer = Socket.pair(:UNIX, :STREAM, 0)
    oversized_reader, oversized_writer = Socket.pair(:UNIX, :STREAM, 0)
    unmasked_writer.write([0x81, 1, 'x'.ord].pack('C*'))
    oversized_writer.write([0x81, 0x80 | 127, described_class::MAX_WEBSOCKET_FRAME_BYTES + 1].pack('CCQ>'))

    expect(server.send(:ws_read_frame, unmasked_reader)).to be_nil
    expect(server.send(:ws_read_frame, oversized_reader)).to be_nil
  ensure
    [unmasked_reader, unmasked_writer, oversized_reader, oversized_writer].compact.each(&:close)
  end

  it 'caps simultaneous connections' do
    described_class::MAX_CONNECTIONS.times { expect(server.send(:claim_connection)).to be(true) }

    expect(server.send(:claim_connection)).to be(false)
  ensure
    described_class::MAX_CONNECTIONS.times { server.send(:release_connection) }
  end

  it 'expires outbound writes to a peer that stops reading' do
    stub_const('Msf::Plugin::NetworkMapLive::LiveServer::WEBSOCKET_WRITE_TIMEOUT', 0.05)
    reader, writer = Socket.pair(:UNIX, :STREAM, 0)
    writer.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 4096)
    client = { sock: writer, write_lock: Mutex.new }

    expect do
      Timeout.timeout(1) { server.send(:ws_send_frame, client, 'x'.b * 1_000_000) }
    end.to raise_error(Errno::ETIMEDOUT)
  ensure
    [reader, writer].compact.each(&:close)
  end

  it 'drops a websocket viewer whose bounded snapshot queue fills' do
    socket = instance_double(TCPSocket, close: nil)
    client = {
      sock: socket, outbox: [], outbox_lock: Mutex.new,
      outbox_condvar: ConditionVariable.new, closed: false
    }
    server.instance_variable_get(:@clients) << client

    Timeout.timeout(1) do
      (described_class::MAX_PENDING_WEBSOCKET_FRAMES + 1).times { server.send(:broadcast, '{}') }
    end

    expect(server.client_count).to eq(0)
    expect(socket).to have_received(:close)
  end

  it 'uses the shared graph builder implementation' do
    expect(described_class.instance_method(:build_graph_data).owner).to eq(Msf::Auxiliary::NetworkGraphBuilder)
  end
end

RSpec.describe Msf::Plugin::NetworkMapLive::EventRelay do
  subject(:relay) { described_class.new(server) }

  let(:server) { instance_double(Msf::Plugin::NetworkMapLive::LiveServer, trigger: nil, record_console_command: nil) }

  it 'refreshes the graph when session routes change' do
    relay.on_session_route(nil, nil)
    relay.on_session_route_remove(nil, nil)

    expect(server).to have_received(:trigger).twice
  end
end

RSpec.describe Msf::Plugin::NetworkMapLive::CommandDispatcher do
  subject(:dispatcher) { described_class.allocate }

  let(:server) do
    instance_double(
      Msf::Plugin::NetworkMapLive::LiveServer,
      running?: false,
      loopback?: true,
      url: 'http://127.0.0.1:4646/',
      start: 'correct horse battery staple'
    )
  end

  before do
    allow(dispatcher).to receive_messages(
      server: server,
      framework: instance_double(Msf::Framework, db: double(active: false)),
      print_error: nil,
      print_good: nil,
      print_line: nil,
      print_status: nil,
      print_warning: nil
    )
  end

  it 'does not interpret option values as the positional port' do
    dispatcher.cmd_network_map_start('--interval', '3', '--limit-session', '10')

    expect(server).to have_received(:start).with(hash_including(port: 4646, interval: 3.0, limits: hash_including(session: 10)))
  end

  it 'requires an explicit flag to share console output' do
    dispatcher.cmd_network_map_start('--console-feed')

    expect(server).to have_received(:start).with(hash_including(console_feed: true))
  end

  it 'rejects an invalid positional port' do
    dispatcher.cmd_network_map_start('not-a-port')

    expect(dispatcher).to have_received(:print_error).with('Invalid port: not-a-port')
    expect(server).not_to have_received(:start)
  end
end

RSpec.describe Msf::Plugin::NetworkMapLive do
  subject(:plugin) do
    described_class.allocate.tap do |instance|
      instance.instance_variable_set(:@console_mutex, Mutex.new)
      instance.instance_variable_set(:@console_state, { version: 0, last_command: nil, tail: [] })
    end
  end

  after { described_class.server = nil }

  it 'includes the D3 license in the live viewer' do
    expect(described_class::INDEX_HTML).to include('Permission to use, copy, modify, and/or distribute this software')
  end

  it 'redacts browser passwords from the shared console feed' do
    described_class.server = instance_double(Msf::Plugin::NetworkMapLive::LiveServer, console_feed?: true)
    plugin.record_console_command('network_map_start --password secret --host 0.0.0.0')
    plugin.record_console_command('network_map_password rotated-secret')
    plugin.record_console_line('Browser password: generated-secret (no username)')
    plugin.record_console_line('Password:  generated-secret (no username)')
    plugin.record_console_line('resource (/tmp/final.rc)> network_map_start --host 0.0.0.0 --password resource-secret')
    plugin.record_console_line('resource (/tmp/final.rc)> network_map_password next-resource-secret')

    snapshot = plugin.console_snapshot
    expect(snapshot.to_s).not_to match(/\b(?:secret|rotated-secret|generated-secret|resource-secret|next-resource-secret)\b/)
    expect(snapshot[:tail].join).to include('[redacted]')
  end

  it 'does not retain console output unless the feed is enabled' do
    described_class.server = instance_double(Msf::Plugin::NetworkMapLive::LiveServer, console_feed?: false)

    plugin.record_console_command('set SMBPass private-secret')
    plugin.record_console_line('Recovered token: private-secret')

    expect(plugin.console_snapshot).to eq(last_command: nil, tail: [])
  end
end
