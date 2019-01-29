# -*- coding: binary -*-
require 'open3'
require 'fileutils'
#require 'rex/proto/ntlm/crypt'
require 'metasploit/framework/hashcat/cracker'
require 'metasploit/framework/jtr/wordlist' #utilize jtr's wordlist for simplicity


module Msf

###
#
# This module provides methods for working with Hashcat
#
###
module Auxiliary::Hashcat
  include Msf::Auxiliary::Report

  #
  # Initializes an instance of an auxiliary module that calls out to Hashcat
  #

  def initialize(info = {})
    super

    register_options(
      [
        OptPath.new('CUSTOM_WORDLIST',      [false, 'The path to an optional custom wordlist']),
        OptInt.new('ITERATION_TIMOUT',      [false, 'The runtime for each iteration of cracking']),
        OptPath.new('HASHCAT_PATH'          [false, 'The absolute path to the Hashcat executable']),
        OptBool.new('MUTATE',               [false, 'Apply common mutations to the Wordlist (SLOW)', false]),
        OptPath.new('POT',                  [false, 'The path to a Hashcat/John POT file to use instead of the default']),
        OptBool.new('USE_CREDS',            [false, 'Use existing credential data saved in the database', true]),
        OptBool.new('USE_DB_INFO',          [false, 'Use looted database schema info to seed the wordlist', true]),
        OptBool.new('USE_DEFAULT_WORDLIST', [false, 'Use the default metasploit wordlist', true]),
        OptBool.new('USE_HOSTNAMES',        [false, 'Seed the wordlist with hostnames from the workspace', true]),
        OptBool.new('USE_ROOT_WORDS',       [false, 'Use the Common Root Words Wordlist', true])
      ], Msf::Auxiliary::Hashcat
    )

  end

  # This method creates a new {Metasploit::Framework::Hashcat::Cracker} and populates
  # some of the attributes based on the module datastore options.
  #
  # @return [nilClass] if there is no active framework db connection
  # @return [Metasploit::Framework::Hashcat::Cracker] if it successfully creates a Hashcat Cracker object
  def new_hashcat_cracker
    return nil unless framework.db.active
    Metasploit::Framework::Hashcat::Cracker.new(
        hashcat_path: datastore['HASHCAT_PATH'],
        max_runtime: datastore['ITERATION_TIMEOUT'],
        pot: datastore['POT'],
        wordlist: datastore['CUSTOM_WORDLIST']
    )
  end

  # This method instantiates a {Metasploit::Framework::JtR::Wordlist}, writes the data
  # out to a file and returns the {Rex::Quickfile} object.  A custom Hashcat dictionary
  # method isn't required, and the JtR one is mirrored here
  #
  # @param max_len [Integer] max length of a word in the wordlist, 0 default for ignored value
  # @return [nilClass] if there is no active framework db connection
  # @return [Rex::Quickfile] if it successfully wrote the wordlist to a file
  def wordlist_file(max_len = 0)
    return nil unless framework.db.active
    wordlist = Metasploit::Framework::JtR::Wordlist.new(
        custom_wordlist: datastore['CUSTOM_WORDLIST'],
        mutate: datastore['MUTATE'],
        use_creds: datastore['USE_CREDS'],
        use_db_info: datastore['USE_DB_INFO'],
        use_default_wordlist: datastore['USE_DEFAULT_WORDLIST'],
        use_hostnames: datastore['USE_HOSTNAMES'],
        use_common_root: datastore['USE_ROOT_WORDS'],
        workspace: myworkspace
    )
    wordlist.to_file(max_len)
  end

end
end
