# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Auxiliary::NetworkGraphBuilder, 'review regressions' do
  subject(:builder) { Object.new.extend(described_class) }

  it 'sanitizes target-controlled hash keys before JSON serialization' do
    input = { 0xff.chr => { 0xfe.chr => '<value>' } }
    out = builder.utf8_sanitize(input)

    expect(out).to eq('?' => { '?' => '<value>' })
    expect { builder.inline_json(input) }.not_to raise_error
  end

  it 'does not create self-links for repeated traceroute hops' do
    traceroute = double(
      data: { 'hops' => [{ 'ipaddr' => '192.0.2.1' }, { 'ipaddr' => '192.0.2.1' }] },
      host: nil
    )
    workspace_data = {
      hosts: [], db_sessions: [], traceroute_notes: [traceroute], host_loots: [],
      host_vulns: [], cve_module_map: {}, snmp_by_host: {}, module_run_events: [],
      direct_module_runs: [], host_cred_logins: []
    }

    _nodes, links = builder.build_graph_data(workspace_data)

    expect(links).not_to include(source: 'hop_192_0_2_1', target: 'hop_192_0_2_1')
  end
end
