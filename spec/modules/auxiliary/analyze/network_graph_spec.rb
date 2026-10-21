# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Network graph module' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:module_instance) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'analyze/network_graph'
    )
  end

  let(:hostile) { "</script><img src=x onerror=alert(1)>'\"&" }
  let(:nodes) do
    [
      {
        id: 'host_1', label: hostile, address: '192.0.2.10', sessions: [],
        services: [], loots: [], vulns: [], creds: [], module_runs: [],
        event_modules: [], snmp_interfaces: [], snmp_lldp: [], snmp_cdp: [],
        snmp_port_hosts: [{ port: hostile, mac: hostile, host_id: hostile, host_label: hostile, host_ip: hostile }],
        device_type: 'computer'
      }
    ]
  end

  before do
    module_instance.datastore['EMBED_JS'] = true
    module_instance.datastore['VERBOSE'] = true
  end

  it 'creates a binary-safe offline report without inline data handlers' do
    html = module_instance.send(:generate_html, nodes, [])

    expect(html.encoding).to eq(Encoding::UTF_8)
    expect(html).to include('https://d3js.org v7.9.0')
    expect(html).to include('Permission to use, copy, modify, and/or distribute this software')
    expect(html).not_to include('cdnjs.cloudflare.com', '</script><img', 'onclick="selectNodeById')
  end

  it 'fails closed when the vendored bundle is missing' do
    d3_path = module_instance.class.const_get(:D3_LOCAL_PATH)
    allow(File).to receive(:file?).and_call_original
    allow(File).to receive(:file?).with(d3_path).and_return(false)

    expect { module_instance.send(:generate_html, nodes, []) }.to raise_error(Msf::Auxiliary::Failed, /D3 local file not found/)
  end

  it 'fails closed when the report template is missing' do
    template_path = module_instance.class.const_get(:TEMPLATE_PATH)
    allow(File).to receive(:file?).and_call_original
    allow(File).to receive(:file?).with(template_path).and_return(false)

    expect { module_instance.send(:generate_html, nodes, []) }.to raise_error(Msf::Auxiliary::Failed, /Network graph template not found/)
  end

  it 'pins the explicitly selected CDN bundle with subresource integrity' do
    module_instance.datastore['EMBED_JS'] = false
    html = module_instance.send(:generate_html, nodes, [])

    expect(html).to include('src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"')
    expect(html).to include('integrity="sha384-CjloA8y00+1SDAUkjs099PVfnY2KmDC2BZnws9kh8D/lX1s46w6EPhpXdqMfjK6i"')
    expect(html).to include("script-src 'unsafe-inline' https://cdnjs.cloudflare.com")
  end

  it 'keeps the committed example synchronized with the hardened template' do
    example_path = Metasploit::Framework.root.join('data/auxiliary/analyze/network_map/example_output.html')
    example = File.binread(example_path).force_encoding(Encoding::UTF_8)

    expect(example).to be_valid_encoding
    expect(example).not_to include('%%D3_CSP_ORIGIN%%', '%%D3_SCRIPT%%', '%%NODES%%', '%%LINKS%%', 'onclick="selectNodeById')
    expect(example).to include("script-src 'unsafe-inline' https://cdnjs.cloudflare.com", 'integrity="sha384-CjloA8y00+1SDAUkjs099PVfnY2KmDC2BZnws9kh8D/lX1s46w6EPhpXdqMfjK6i"', '<span>Vulnerabilities (', 'Permission to use, copy, modify, and/or distribute this software')

    nodes = JSON.parse(example.match(/const NODES = (.*?);\n  const LINKS =/m)[1])
    credentials = nodes.flat_map { |node| node.fetch('creds', []) }
    expect(credentials).to all(satisfy { |credential| credential['username'].start_with?('faker_') })
    expect(nodes.find { |node| node['address'] == '172.16.5.30' }['creds'].first['username']).to eq('faker_hypervisor_admin_susannah')
  end

  it 'documents and verifies the vendored D3 bundle' do
    data_path = Metasploit::Framework.root.join('data/auxiliary/analyze/network_map')
    license = File.read(Metasploit::Framework.root.join('LICENSE'))

    expect(Digest::SHA256.file(data_path.join('d3.v7.9.0.min.js')).hexdigest).to eq('f2094bbf6141b359722c4fe454eb6c4b0f0e42cc10cc7af921fc158fceb86539')
    expect(license).to include("Files: data/auxiliary/analyze/network_map/d3.v7.9.0.min.js\nSource: https://github.com/d3/d3/tree/v7.9.0\nCopyright: 2010-2023 Mike Bostock\nLicense: ISC")
    expect(license).to include("License: ISC\n Permission to use, copy, modify, and/or distribute this software")
  end
end
