module Metasploit
  module Framework
    module Hashcat

      class HashcatNotFoundError < StandardError
      end

      class Cracker
        include ActiveModel::Validations

        # @!attribute format
        #   @return [String] The hash format to try
        attr_accessor :format

        # @!attribute hash_path
        #   @return [String] The path to the file containing the hashes
        attr_accessor :hash_path

        # @!attribute increment
        #   @return [String] The increment mode to use
        attr_accessor :increment

        # @!attribute hashcat_path
        #   This attribute allows the user to specify a hashcat binary to use.
        #   If not supplied, the Cracker will search the PATH for a suitable hashcat binary.
        #
        #   @return [String] The file path to an alternative hashcat binary to use
        attr_accessor :hashcat_path

        # @!attribute max_runtime
        #   @return [Integer] An optional maximum duration of the cracking attempt in seconds
        attr_accessor :max_runtime

        # @!attribute pot
        #   @return [String] The file path to an alternative hashcat pot file to use
        attr_accessor :pot

        # @!attribute rules
        #   @return [String] The wordlist mangling rules to use inside hashcat
        attr_accessor :rules

        # @!attribute wordlist
        #   @return [String] The file path to the wordlist to use
        attr_accessor :wordlist

        validates :hash_path, :'Metasploit::Framework::File_path' => true, if: 'hash_path.present?'

        validates :hashcat_path, :'Metasploit::Framework::Executable_path' => true, if: 'hashcat_path.present?'

        validates :pot, :'Metasploit::Framework::File_path' => true, if: 'pot.present?'

        validates :max_runtime,
                  numericality: {
                      only_integer:             true,
                      greater_than_or_equal_to: 0
                  }, if: 'max_runtime.present?'

        validates :wordlist, :'Metasploit::Framework::File_path' => true, if: 'wordlist.present?'

        # @param attributes [Hash{Symbol => String,nil}]
        def initialize(attributes={})
          attributes.each do |attribute, value|
            public_send("#{attribute}=", value)
          end
        end

        # This method follows a decision tree to determine the path
        # to the hashcat binary we should use.
        #
        # @return [NilClass] if a binary path could not be found
        # @return [String] the path to the selected hashcat binary
        def binary_path
          # Always prefer a manually entered path
          if hashcat_path && ::File.file?(hashcat_path)
            bin_path = hashcat_path
          else
            # Look in the Environment PATH for the john binary
            path = Rex::FileUtils.find_full_path("hashcat") ||
                Rex::FileUtils.find_full_path("hashcat.exe")

            if path && ::File.file?(path)
              bin_path = path
            end
          end
          raise HashcatNotFoundError, 'No suitable Hashcat binary was found on the system' if bin_path.blank?
          bin_path
        end

        # This method runs the command from {#crack_command} and yields each line of output.
        #
        # @yield [String] a line of output from the john command
        # @return [void]
        def crack
          ::IO.popen(crack_command, "rb") do |fd|
            fd.each_line do |line|
              yield line
            end
          end
        end

        # This method builds an array for the command to actually run the cracker.
        # It builds the command from all of the attributes on the class.
        #
        # @raise [JohnNotFoundError] if a suitable John binary was never found
        # @return [Array] An array set up for {::IO.popen} to use
        def crack_command
          cmd_string = binary_path
          cmd = [ cmd_string,  '--session=' + john_session_id, '--nolog' ]

          if pot.present?
            cmd << ( "--potfile-path=" + pot )
          else
            cmd << ( "--potfile-path=" + john_pot_file)
          end

          if format.present?
            cmd << ( "--hash-type=" + format )
          end

          if increment.present?
            cmd << ( "--increment")
          end

          if rules.present?
            cmd << ( "--rules-file=" + rules )
          end

          if max_runtime.present?
            cmd << ( "--runtime=" + max_runtime.to_s)
          end

          cmd << hash_path

          if wordlist.present?
            cmd << ( wordlist )
          end

        end

        # This runs the show command in john and yields cracked passwords.
        #
        # @yield [String] the output lines from the command
        # @return [void]
        def each_cracked_password
          ::IO.popen(show_command, "rb") do |fd|
            fd.each_line do |line|
              yield line
            end
          end
        end

        # This method returns the path to a default john.pot file.
        # For simplicity of cracking between jtr/hashcat, the john.pot
        # file from jtr is used
        #
        # @return [String] the path to the default john.pot file
        def hashcat_pot_file
          ::File.join( ::Msf::Config.config_directory, "john.pot" )
        end

        # This method is a getter for a random Session ID for Hashcat.
        # It allows us to dinstiguish between cracking sessions.
        #
        # @ return [String] the Session ID to use
        def hashcat_session_id
          @session_id ||= ::Rex::Text.rand_text_alphanumeric(8)
        end

        # This method builds the command to show the cracked passwords.
        #
        # @raise [HashcatNotFoundError] if a suitable Hashcat binary was never found
        # @return [Array] An array set up for {::IO.popen} to use
        def show_command
          cmd_string = binary_path

          pot_file = pot || john_pot_file
          cmd = [cmd_string, "--show", "--pot=#{pot_file}", "--hash-type=#{format}" ]

          cmd << hash_path
        end

        private

      end

    end
  end
end
