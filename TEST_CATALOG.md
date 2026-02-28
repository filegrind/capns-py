# Capns-Py Test Catalog

**Total Tests:** 398

This catalog lists all numbered tests in the capns-py codebase.

| Test # | Function Name | Description | Location |
|--------|---------------|-------------|----------|
| test001 | `test_001_cap_urn_creation` | TEST001: Test that cap URN is created with tags parsed correctly and direction specs accessible | tests/test_cap_urn.py:29 |
| test002 | `test_002_direction_specs_default_to_wildcard` | TEST002: Test that missing 'in' or 'out' defaults to media: wildcard | tests/test_cap_urn.py:40 |
| test003 | `test_003_direction_matching` | TEST003: Test that direction specs must match exactly, different in/out types don't match, wildcard matches any | tests/test_cap_urn.py:58 |
| test004 | `test_004_unquoted_values_lowercased` | TEST004: Test that unquoted keys and values are normalized to lowercase | tests/test_cap_urn.py:86 |
| test005 | `test_005_quoted_values_preserve_case` | TEST005: Test that quoted values preserve case while unquoted are lowercased | tests/test_cap_urn.py:106 |
| test006 | `test_006_quoted_value_special_chars` | TEST006: Test that quoted values can contain special characters (semicolons, equals, spaces) | tests/test_cap_urn.py:124 |
| test007 | `test_007_quoted_value_escape_sequences` | TEST007: Test that escape sequences in quoted values (\" and \\) are parsed correctly | tests/test_cap_urn.py:139 |
| test008 | `test_008_mixed_quoted_unquoted` | TEST008: Test that mixed quoted and unquoted values in same URN parse correctly | tests/test_cap_urn.py:154 |
| test009 | `test_009_unterminated_quote_error` | TEST009: Test that unterminated quote produces UnterminatedQuote error | tests/test_cap_urn.py:161 |
| test010 | `test_010_invalid_escape_sequence_error` | TEST010: Test that invalid escape sequences (like \n, \x) produce InvalidEscapeSequence error | tests/test_cap_urn.py:167 |
| test011 | `test_011_serialization_smart_quoting` | TEST011: Test that serialization uses smart quoting (no quotes for simple lowercase, quotes for special chars/uppercase) | tests/test_cap_urn.py:177 |
| test012 | `test_012_round_trip_simple` | TEST012: Test that simple cap URN round-trips (parse -> serialize -> parse equals original) | tests/test_cap_urn.py:196 |
| test013 | `test_013_round_trip_quoted` | TEST013: Test that quoted values round-trip preserving case and spaces | tests/test_cap_urn.py:205 |
| test014 | `test_014_round_trip_escapes` | TEST014: Test that escape sequences round-trip correctly | tests/test_cap_urn.py:215 |
| test015 | `test_015_cap_prefix_required` | TEST015: Test that cap: prefix is required and case-insensitive | tests/test_cap_urn.py:225 |
| test016 | `test_016_trailing_semicolon_equivalence` | TEST016: Test that trailing semicolon is equivalent (same hash, same string, matches) | tests/test_cap_urn.py:240 |
| test017 | `test_017_tag_matching` | TEST017: Test tag matching: exact match, subset match, wildcard match, value mismatch | tests/test_cap_urn.py:260 |
| test018 | `test_018_quoted_values_case_sensitive` | TEST018: Test that quoted values with different case do NOT match (case-sensitive) | tests/test_cap_urn.py:282 |
| test019 | `test_019_missing_tags_as_wildcards` | TEST019: Test that missing tags are treated as wildcards (cap without tag matches any value for that tag) | tests/test_cap_urn.py:289 |
| test020 | `test_020_specificity_calculation` | TEST020: Test specificity calculation (direction specs use MediaUrn tag count, wildcards don't count) | tests/test_cap_urn.py:301 |
| test021 | `test_021_builder_creates_cap_urn` | TEST021: Test builder creates cap URN with correct tags and direction specs | tests/test_cap_urn.py:315 |
| test022 | `test_022_builder_requires_direction_specs` | TEST022: Test builder requires both in_spec and out_spec | tests/test_cap_urn.py:331 |
| test023 | `test_023_builder_key_normalization` | TEST023: Test builder lowercases keys but preserves value case | tests/test_cap_urn.py:346 |
| test024 | `test_024_directional_accepts` | TEST024: Test directional accepts (different op values, wildcard, direction mismatch) | tests/test_cap_urn.py:362 |
| test025 | `test_025_find_best_match` | TEST025: Test find_best_match returns most specific matching cap | tests/test_cap_urn.py:383 |
| test026 | `test_026_merge_and_subset` | TEST026: Test merge combines tags from both caps, subset keeps only specified tags | tests/test_cap_urn.py:400 |
| test027 | `test_027_with_wildcard_tag` | TEST027: Test with_wildcard_tag sets tag to wildcard, including in/out | tests/test_cap_urn.py:417 |
| test028 | `test_028_empty_cap_urn_defaults` | TEST028: Test bare "cap:" defaults to media: for both directions (identity morphism) | tests/test_cap_urn.py:434 |
| test029 | `test_029_minimal_valid_cap_urn` | TEST029: Test minimal valid cap URN has just in and out, empty tags | tests/test_cap_urn.py:442 |
| test030 | `test_030_extended_characters_in_values` | TEST030: Test extended characters (forward slashes, colons) in tag values | tests/test_cap_urn.py:450 |
| test031 | `test_031_wildcard_in_keys_and_values` | TEST031: Test wildcard rejected in keys but accepted in values | tests/test_cap_urn.py:457 |
| test032 | `test_032_duplicate_keys_rejected` | TEST032: Test duplicate keys are rejected with DuplicateKey error | tests/test_cap_urn.py:468 |
| test033 | `test_033_numeric_keys` | TEST033: Test pure numeric keys rejected, mixed alphanumeric allowed, numeric values allowed | tests/test_cap_urn.py:474 |
| test034 | `test_034_empty_values_rejected` | TEST034: Test empty values are rejected | tests/test_cap_urn.py:489 |
| test035 | `test_035_has_tag_behavior` | TEST035: Test has_tag is case-sensitive for values, case-insensitive for keys, works for in/out | tests/test_cap_urn.py:496 |
| test036 | `test_036_with_tag_preserves_case` | TEST036: Test with_tag preserves value case | tests/test_cap_urn.py:515 |
| test037 | `test_037_with_tag_rejects_empty` | TEST037: Test with_tag rejects empty value | tests/test_cap_urn.py:522 |
| test038 | `test_038_semantic_equivalence_quoted_unquoted` | TEST038: Test semantic equivalence of unquoted and quoted simple lowercase values | tests/test_cap_urn.py:529 |
| test039 | `test_039_get_tag_direction_specs` | TEST039: Test get_tag returns direction specs (in/out) with case-insensitive lookup | tests/test_cap_urn.py:538 |
| test040 | `test_040_matching_semantics_exact_match` | TEST040: Matching semantics - exact match succeeds | tests/test_cap_urn.py:562 |
| test041 | `test_041_matching_semantics_cap_missing_tag` | TEST041: Matching semantics - cap missing tag matches (implicit wildcard) | tests/test_cap_urn.py:569 |
| test042 | `test_042_matching_semantics_cap_has_extra_tag` | TEST042: Pattern rejects instance missing required tags | tests/test_cap_urn.py:576 |
| test043 | `test_043_matching_semantics_request_has_wildcard` | TEST043: Matching semantics - request wildcard matches specific cap value | tests/test_cap_urn.py:586 |
| test044 | `test_044_matching_semantics_cap_has_wildcard` | TEST044: Matching semantics - cap wildcard matches specific request value | tests/test_cap_urn.py:593 |
| test045 | `test_045_matching_semantics_value_mismatch` | TEST045: Matching semantics - value mismatch does not match | tests/test_cap_urn.py:600 |
| test046 | `test_046_matching_semantics_fallback_pattern` | TEST046: Matching semantics - fallback pattern (cap missing tag = implicit wildcard) | tests/test_cap_urn.py:607 |
| test047 | `test_047_matching_semantics_thumbnail_void_input` | TEST047: Matching semantics - thumbnail fallback with void input | tests/test_cap_urn.py:615 |
| test048 | `test_048_matching_semantics_wildcard_direction` | TEST048: Matching semantics - wildcard direction matches anything | tests/test_cap_urn.py:623 |
| test049 | `test_049_matching_semantics_cross_dimension` | TEST049: Non-overlapping tags — neither direction accepts | tests/test_cap_urn.py:630 |
| test050 | `test_050_matching_semantics_direction_mismatch` | TEST050: Matching semantics - direction mismatch prevents matching | tests/test_cap_urn.py:639 |
| test051 | `test_051_direction_semantic_matching` | TEST051: Semantic direction matching - generic provider matches specific request | tests/test_cap_urn.py:648 |
| test052 | `test_052_direction_semantic_specificity` | TEST052: Semantic direction specificity - more media URN tags = higher specificity | tests/test_cap_urn.py:696 |
| test060 | `test_060_wrong_prefix_fails` | TEST060: Test wrong prefix fails with InvalidPrefix error showing expected and actual prefix | tests/test_media_urn.py:42 |
| test061 | `test_061_is_binary` | TEST061: Test is_binary returns true when textable marker tag is NOT present | tests/test_media_urn.py:48 |
| test062 | `test_062_is_record` | TEST062: Test is_record returns true when record marker tag is present indicating key-value structure | tests/test_media_urn.py:62 |
| test063 | `test_063_is_scalar` | TEST063: Test is_scalar returns true when list marker tag is NOT present indicating single value | tests/test_media_urn.py:76 |
| test064 | `test_064_is_list` | TEST064: Test is_list returns true when list marker tag is present indicating ordered collection | tests/test_media_urn.py:89 |
| test065 | `test_065_is_structured` | TEST065: Test is_structured returns true for record or list indicating structured data types | tests/test_media_urn.py:102 |
| test066 | `test_066_is_json` | TEST066: Test is_json returns true only when json marker tag is present for JSON representation | tests/test_media_urn.py:125 |
| test067 | `test_067_is_text` | TEST067: Test is_text returns true only when textable marker tag is present | tests/test_media_urn.py:135 |
| test068 | `test_068_is_void` | TEST068: Test is_void returns true when void flag or type=void tag is present | tests/test_media_urn.py:148 |
| test071 | `test_071_to_string_roundtrip` | TEST071: Test to_string roundtrip ensures serialization and deserialization preserve URN structure | tests/test_media_urn.py:158 |
| test072 | `test_072_all_constants_parse` | TEST072: Test all media URN constants parse successfully as valid media URNs | tests/test_media_urn.py:167 |
| test073 | `test_073_extension_helpers` | TEST073: Test extension helper functions create media URNs with ext tag and correct format | tests/test_media_urn.py:188 |
| test074 | `test_074_media_urn_matching` | TEST074: Test media URN matching using tagged URN semantics with specific and generic requirements | tests/test_media_urn.py:212 |
| test075 | `test_075_matching` | TEST075: Test matching with implicit wildcards where handlers with fewer tags can handle more requests | tests/test_media_urn.py:220 |
| test076 | `test_076_specificity` | TEST076: Test specificity increases with more tags for ranking matches | tests/test_media_urn.py:230 |
| test077 | `test_077_serde_roundtrip` | TEST077: Test serde roundtrip serializes to JSON string and deserializes back correctly | tests/test_media_urn.py:240 |
| test095 | `test_095_media_spec_def_serialize` | TEST095: Test MediaSpecDef serializes with required fields and skips None fields | tests/test_media_spec.py:182 |
| test096 | `test_096_media_spec_def_deserialize` | TEST096: Test deserializing MediaSpecDef from JSON object | tests/test_media_spec.py:206 |
| test097 | `test_097_validate_no_duplicate_urns_catches_duplicates` | TEST097: Test duplicate URN validation catches duplicates | tests/test_media_spec.py:225 |
| test098 | `test_098_validate_no_duplicate_urns_passes_for_unique` | TEST098: Test duplicate URN validation passes for unique URNs | tests/test_media_spec.py:244 |
| test099 | `test_099_resolved_is_binary` | TEST099: Test ResolvedMediaSpec is_binary returns true for non-textable media URN | tests/test_media_spec.py:267 |
| test100 | `test_100_resolved_is_record` | TEST100: Test ResolvedMediaSpec is_record returns true for record marker tag media URN | tests/test_media_spec.py:285 |
| test101 | `test_101_resolved_is_scalar` | TEST101: Test ResolvedMediaSpec is_scalar returns true when list marker tag is NOT present | tests/test_media_spec.py:304 |
| test102 | `test_102_resolved_is_list` | TEST102: Test ResolvedMediaSpec is_list returns true for list marker tag media URN | tests/test_media_spec.py:322 |
| test103 | `test_103_resolved_is_json` | TEST103: Test ResolvedMediaSpec is_json returns true when json marker tag is present | tests/test_media_spec.py:340 |
| test104 | `test_104_resolved_is_text` | TEST104: Test ResolvedMediaSpec is_text returns true when textable tag is present | tests/test_media_spec.py:358 |
| test108 | `test_108_extensions_serialization` | TEST108: Test extensions serializes/deserializes correctly in MediaSpecDef | tests/test_media_spec.py:475 |
| test108 | `test_108_cap_creation` | TEST108: Test Cap creation with URN, title, and command | tests/test_cap.py:19 |
| test109 | `test_109_cap_with_args` | TEST109: Test Cap with args stores and retrieves arguments correctly | tests/test_cap.py:30 |
| test110 | `test_110_cap_with_stdin` | TEST110: Test Cap with stdin source stores stdin media URN correctly | tests/test_cap.py:49 |
| test111 | `test_111_cap_without_stdin` | TEST111: Test Cap with no stdin returns None for get_stdin_media_urn | tests/test_cap.py:65 |
| test112 | `test_112_cap_with_output` | TEST112: Test Cap with output stores output definition correctly | tests/test_cap.py:81 |
| test113 | `test_113_cap_with_metadata` | TEST113: Test Cap with metadata stores and retrieves metadata correctly | tests/test_cap.py:97 |
| test114 | `test_114_cap_json_serialization` | TEST114: Test Cap JSON serialization includes all fields | tests/test_cap.py:110 |
| test115 | `test_115_cap_json_roundtrip` | TEST115: Test Cap JSON deserialization roundtrip preserves all data | tests/test_cap.py:143 |
| test116 | `test_116_cap_arg_multiple_sources` | TEST116: Test CapArg with multiple sources stores all source types | tests/test_cap.py:168 |
| test117 | `test_117_register_and_find_cap_set` | TEST117: Test registering cap set and finding by exact and subset matching | tests/test_cap_matrix.py:39 |
| test118 | `test_118_best_cap_set_selection` | TEST118: Test selecting best cap set based on specificity ranking | tests/test_cap_matrix.py:62 |
| test119 | `test_119_invalid_urn_handling` | TEST119: Test invalid URN returns InvalidUrn error | tests/test_cap_matrix.py:89 |
| test120 | `test_120_accepts_request` | TEST120: Test accepts_request checks if registry can accept a capability request | tests/test_cap_matrix.py:97 |
| test121 | `test_121_cap_block_more_specific_wins` | TEST121: Test CapBlock selects more specific cap over less specific regardless of registry order | tests/test_cap_matrix.py:380 |
| test122 | `test_122_cap_block_tie_goes_to_first` | TEST122: Test CapBlock breaks specificity ties by first registered registry | tests/test_cap_matrix.py:421 |
| test123 | `test_123_cap_block_polls_all` | TEST123: Test CapBlock polls all registries to find most specific match | tests/test_cap_matrix.py:448 |
| test124 | `test_124_cap_block_no_match` | TEST124: Test CapBlock returns error when no registries match the request | tests/test_cap_matrix.py:482 |
| test125 | `test_125_cap_block_fallback_scenario` | TEST125: Test CapBlock prefers specific plugin over generic provider fallback | tests/test_cap_matrix.py:496 |
| test126 | `test_126_cap_block_accepts_request` | TEST126: Test CapBlock accepts_request method checks if any registry can accept the capability | tests/test_cap_matrix.py:536 |
| test127 | `test_127_cap_graph_adds_nodes_and_edges` | TEST127: Test CapGraph adds nodes and edges from capability definitions | tests/test_cap_matrix.py:120 |
| test128 | `test_128_cap_graph_tracks_outgoing_and_incoming` | TEST128: Test CapGraph tracks outgoing and incoming edges for spec conversions | tests/test_cap_matrix.py:145 |
| test129 | `test_129_cap_graph_detects_conversion_paths` | TEST129: Test CapGraph detects direct and indirect conversion paths between specs | tests/test_cap_matrix.py:166 |
| test130 | `test_130_cap_graph_finds_shortest_path` | TEST130: Test CapGraph finds shortest path for spec conversion chain | tests/test_cap_matrix.py:193 |
| test131 | `test_131_cap_graph_finds_all_paths` | TEST131: Test CapGraph finds all conversion paths sorted by length | tests/test_cap_matrix.py:215 |
| test132 | `test_132_cap_graph_direct_edges_sorted_by_specificity` | TEST132: Test CapGraph returns direct edges sorted by specificity | tests/test_cap_matrix.py:239 |
| test133 | `test_133_cap_block_graph_integration` | TEST133: Test CapBlock graph integration with multiple registries and conversion paths | tests/test_cap_matrix.py:557 |
| test134 | `test_134_cap_graph_stats` | TEST134: Test CapGraph stats provides counts of nodes and edges | tests/test_cap_matrix.py:261 |
| test135 | `test_135_registry_creation` | TEST135: Test registry creation with temporary cache directory succeeds | tests/test_registry.py:31 |
| test136 | `test_136_cache_key_generation` | TEST136: Test cache key generation produces consistent hashes for same URN | tests/test_registry.py:43 |
| test137 | `test_137_parse_registry_json` | TEST137: Test parsing registry JSON without stdin args verifies cap structure | tests/test_registry.py:68 |
| test138 | `test_138_parse_registry_json_with_stdin` | TEST138: Test parsing registry JSON with stdin args verifies stdin media URN extraction | tests/test_registry.py:113 |
| test139 | `test_139_url_keeps_cap_prefix_literal` | TEST139: Test URL construction keeps cap prefix literal and only encodes tags part | tests/test_registry.py:136 |
| test140 | `test_140_url_encodes_quoted_media_urns` | TEST140: Test URL encodes media URNs with proper percent encoding for special characters | tests/test_registry.py:153 |
| test141 | `test_141_exact_url_format` | TEST141: Test exact URL format contains properly encoded media URN components | tests/test_registry.py:173 |
| test142 | `test_142_normalize_handles_different_tag_orders` | TEST142: Test normalize handles different tag orders producing same canonical form | tests/test_registry.py:190 |
| test143 | `test_143_default_config` | TEST143: Test default config uses capns.org or environment variable values | tests/test_registry.py:203 |
| test144 | `test_144_custom_registry_url` | TEST144: Test custom registry URL updates both registry and schema base URLs | tests/test_registry.py:213 |
| test145 | `test_145_custom_registry_and_schema_url` | TEST145: Test custom registry and schema URLs set independently | tests/test_registry.py:222 |
| test146 | `test_146_schema_url_not_overwritten_when_explicit` | TEST146: Test schema URL not overwritten when set explicitly before registry URL | tests/test_registry.py:233 |
| test147 | `test_147_registry_for_test_with_config` | TEST147: Test registry for test with custom config creates registry with specified URLs | tests/test_registry.py:245 |
| test148 | `test_148_cap_manifest_creation` | TEST148: Test creating cap manifest with name, version, description, and caps | tests/test_manifest.py:20 |
| test149 | `test_149_cap_manifest_with_author` | TEST149: Test cap manifest with author field sets author correctly | tests/test_manifest.py:39 |
| test150 | `test_150_cap_manifest_json_serialization` | TEST150: Test cap manifest JSON serialization and deserialization roundtrip | tests/test_manifest.py:54 |
| test151 | `test_151_cap_manifest_required_fields` | TEST151: Test cap manifest deserialization fails when required fields are missing | tests/test_manifest.py:91 |
| test152 | `test_152_cap_manifest_with_multiple_caps` | TEST152: Test cap manifest with multiple caps stores and retrieves all capabilities | tests/test_manifest.py:103 |
| test153 | `test_153_cap_manifest_with_page_url` | TEST153: Test cap manifest with page_url field sets page URL correctly | tests/test_manifest.py:128 |
| test154 | `test_154_cap_manifest_optional_fields` | TEST154: Test cap manifest JSON includes optional fields only when set | tests/test_manifest.py:143 |
| test155 | `test_155_cap_manifest_complex_roundtrip` | TEST155: Test cap manifest roundtrip preserves all data including nested cap structures | tests/test_manifest.py:167 |
| test156 | `test_156_stdin_source_data_creation` | TEST156: Test creating StdinSource Data variant with byte vector | tests/test_caller.py:30 |
| test157 | `test_157_stdin_source_file_reference_creation` | TEST157: Test creating StdinSource FileReference variant with all required fields | tests/test_caller.py:39 |
| test158 | `test_158_stdin_source_data_empty` | TEST158: Test StdinSource Data with empty vector stores and retrieves correctly | tests/test_caller.py:59 |
| test159 | `test_159_stdin_source_data_binary` | TEST159: Test StdinSource Data with binary content like PNG header bytes | tests/test_caller.py:66 |
| test160 | `test_160_stdin_source_data_clone` | TEST160: Test StdinSource Data clone creates independent copy with same data | tests/test_caller.py:77 |
| test161 | `test_161_stdin_source_file_reference_clone` | TEST161: Test StdinSource FileReference clone creates independent copy with same fields | tests/test_caller.py:95 |
| test162 | `test_162_stdin_source_debug_format` | TEST162: Test StdinSource Debug format displays variant type and relevant fields | tests/test_caller.py:115 |
| test163 | `test_163_argument_schema_validation_success` | TEST163: Test argument schema validation succeeds with valid JSON matching schema | tests/test_schema_validation.py:25 |
| test164 | `test_164_argument_schema_validation_failure` | TEST164: Test argument schema validation fails with JSON missing required fields | tests/test_schema_validation.py:56 |
| test165 | `test_165_output_schema_validation_success` | TEST165: Test output schema validation succeeds with valid JSON matching schema | tests/test_schema_validation.py:89 |
| test166 | `test_166_skip_validation_without_schema` | TEST166: Test validation skipped when resolved media spec has no schema | tests/test_schema_validation.py:120 |
| test167 | `test_167_unresolved_media_urn_skips_validation` | TEST167: Test validation with unresolved media URN skips validation gracefully | tests/test_schema_validation.py:136 |
| test168 | `test_168_json_response` | TEST168: Test ResponseWrapper from JSON deserializes to correct structured type | tests/test_response.py:20 |
| test169 | `test_169_primitive_types` | TEST169: Test ResponseWrapper converts to primitive types integer, float, boolean, string | tests/test_response.py:31 |
| test170 | `test_170_binary_response` | TEST170: Test ResponseWrapper from binary stores and retrieves raw bytes correctly | tests/test_response.py:50 |
| test171 | `test_171_frame_type_roundtrip` | TEST171: Test all FrameType discriminants roundtrip through u8 conversion preserving identity | tests/test_cbor_frame.py:22 |
| test172 | `test_172_invalid_frame_type` | TEST172: Test FrameType::from_u8 returns None for values outside the valid discriminant range | tests/test_cbor_frame.py:43 |
| test173 | `test_173_frame_type_discriminant_values` | TEST173: Test FrameType discriminant values match the wire protocol specification exactly | tests/test_cbor_frame.py:53 |
| test174 | `test_174_message_id_uuid` | TEST174: Test MessageId::new_uuid generates valid UUID that roundtrips through string conversion | tests/test_cbor_frame.py:68 |
| test175 | `test_175_message_id_uuid_uniqueness` | TEST175: Test two MessageId::new_uuid calls produce distinct IDs (no collisions) | tests/test_cbor_frame.py:79 |
| test176 | `test_176_message_id_uint_has_no_uuid_string` | TEST176: Test MessageId::Uint does not produce a UUID string, to_uuid_string returns None | tests/test_cbor_frame.py:87 |
| test177 | `test_177_message_id_from_invalid_uuid_str` | TEST177: Test MessageId::from_uuid_str rejects invalid UUID strings | tests/test_cbor_frame.py:94 |
| test178 | `test_178_message_id_as_bytes` | TEST178: Test MessageId::as_bytes produces correct byte representations for Uuid and Uint variants | tests/test_cbor_frame.py:102 |
| test179 | `test_179_message_id_default_is_uuid` | TEST179: Test MessageId::default creates a UUID variant (not Uint) | tests/test_cbor_frame.py:115 |
| test180 | `test_180_hello_frame` | TEST180: Test Frame::hello without manifest produces correct HELLO frame for host side | tests/test_cbor_frame.py:122 |
| test181 | `test_181_hello_frame_with_manifest` | TEST181: Test Frame::hello_with_manifest produces HELLO with manifest bytes for plugin side | tests/test_cbor_frame.py:136 |
| test182 | `test_182_req_frame` | TEST182: Test Frame::req stores cap URN, payload, and content_type correctly | tests/test_cbor_frame.py:149 |
| test184 | `test_184_chunk_frame` | TEST184: Test Frame::chunk stores stream_id, seq and payload for streaming | tests/test_cbor_frame.py:165 |
| test185 | `test_185_err_frame` | TEST185: Test Frame::err stores error code and message in metadata | tests/test_cbor_frame.py:181 |
| test186 | `test_186_log_frame` | TEST186: Test Frame::log stores level and message in metadata | tests/test_cbor_frame.py:191 |
| test187 | `test_187_end_frame_with_payload` | TEST187: Test Frame::end with payload sets eof and optional final payload | tests/test_cbor_frame.py:202 |
| test188 | `test_188_end_frame_without_payload` | TEST188: Test Frame::end without payload still sets eof marker | tests/test_cbor_frame.py:212 |
| test189 | `test_189_chunk_with_offset` | TEST189: Test chunk_with_offset sets offset on all chunks but len only on seq=0 | tests/test_cbor_frame.py:222 |
| test190 | `test_190_heartbeat_frame` | TEST190: Test Frame::heartbeat creates minimal frame with no payload or metadata | tests/test_cbor_frame.py:246 |
| test191 | `test_191_error_accessors_on_non_err_frame` | TEST191: Test error_code and error_message return None for non-Err frame types | tests/test_cbor_frame.py:258 |
| test192 | `test_192_log_accessors_on_non_log_frame` | TEST192: Test log_level and log_message return None for non-Log frame types | tests/test_cbor_frame.py:269 |
| test193 | `test_193_hello_accessors_on_non_hello_frame` | TEST193: Test hello_max_frame and hello_max_chunk return None for non-Hello frame types | tests/test_cbor_frame.py:277 |
| test194 | `test_194_frame_new_defaults` | TEST194: Test Frame::new sets version and defaults correctly, optional fields are None | tests/test_cbor_frame.py:286 |
| test195 | `test_195_frame_default` | TEST195: Test Frame::default creates a Req frame (the documented default) | tests/test_cbor_frame.py:304 |
| test196 | `test_196_is_eof_when_none` | TEST196: Test is_eof returns false when eof field is None (unset) | tests/test_cbor_frame.py:312 |
| test197 | `test_197_is_eof_when_false` | TEST197: Test is_eof returns false when eof field is explicitly Some(false) | tests/test_cbor_frame.py:319 |
| test198 | `test_198_limits_default` | TEST198: Test Limits::default provides the documented default values | tests/test_cbor_frame.py:327 |
| test199 | `test_199_protocol_version_constant` | TEST199: Test PROTOCOL_VERSION is 2 | tests/test_cbor_frame.py:337 |
| test200 | `test_200_key_constants` | TEST200: Test integer key constants match the protocol specification | tests/test_cbor_frame.py:343 |
| test201 | `test_201_hello_manifest_binary_data` | TEST201: Test hello_with_manifest preserves binary manifest data (not just JSON text) | tests/test_cbor_frame.py:359 |
| test202 | `test_202_message_id_equality_and_hash` | TEST202: Test MessageId Eq/Hash semantics: equal UUIDs are equal, different ones are not | tests/test_cbor_frame.py:367 |
| test203 | `test_203_message_id_cross_variant_inequality` | TEST203: Test Uuid and Uint variants of MessageId are never equal even for coincidental byte values | tests/test_cbor_frame.py:390 |
| test204 | `test_204_req_frame_empty_payload` | TEST204: Test Frame::req with empty payload stores Some(empty vec) not None | tests/test_cbor_frame.py:398 |
| test205 | `test_205_encode_frame_produces_cbor_with_integer_keys` | TEST205: Test encode_frame produces CBOR with integer keys | tests/test_cbor_io.py:35 |
| test206 | `test_206_decode_frame_parses_cbor_correctly` | TEST206: Test decode_frame parses CBOR frame correctly | tests/test_cbor_io.py:53 |
| test207 | `test_207_decode_frame_fails_on_invalid_cbor` | TEST207: Test decode_frame fails on invalid CBOR | tests/test_cbor_io.py:65 |
| test208 | `test_208_decode_frame_fails_on_non_map` | TEST208: Test decode_frame fails on non-map CBOR | tests/test_cbor_io.py:71 |
| test209 | `test_209_write_frame_writes_length_prefixed` | TEST209: Test write_frame writes length-prefixed frame | tests/test_cbor_io.py:80 |
| test210 | `test_210_read_frame_reads_length_prefixed` | TEST210: Test read_frame reads length-prefixed frame | tests/test_cbor_io.py:96 |
| test211 | `test_211_read_frame_returns_none_on_eof` | TEST211: Test read_frame returns None on EOF | tests/test_cbor_io.py:113 |
| test212 | `test_212_read_frame_fails_on_incomplete_length_prefix` | TEST212: Test read_frame fails on incomplete length prefix | tests/test_cbor_io.py:122 |
| test213 | `test_213_read_frame_fails_on_incomplete_frame_data` | TEST213: Test read_frame fails on incomplete frame data | tests/test_cbor_io.py:131 |
| test214 | `test_214_write_frame_enforces_max_frame_size` | TEST214: Test write_frame enforces max frame size | tests/test_cbor_io.py:141 |
| test215 | `test_215_frame_reader_reads_multiple_frames` | TEST215: Test FrameReader reads multiple frames | tests/test_cbor_io.py:154 |
| test216 | `test_216_frame_writer_writes_multiple_frames` | TEST216: Test FrameWriter writes multiple frames | tests/test_cbor_io.py:178 |
| test217 | `test_217_frame_reader_new_creates_with_default_limits` | TEST217: Test FrameReader.new creates with default limits | tests/test_cbor_io.py:201 |
| test218 | `test_218_frame_writer_new_creates_with_default_limits` | TEST218: Test FrameWriter.new creates with default limits | tests/test_cbor_io.py:210 |
| test219 | `test_219_frame_reader_with_limits` | TEST219: Test FrameReader.with_limits creates with specified limits | tests/test_cbor_io.py:219 |
| test220 | `test_220_frame_writer_with_limits` | TEST220: Test FrameWriter.with_limits creates with specified limits | tests/test_cbor_io.py:229 |
| test221 | `test_221_frame_reader_set_limits` | TEST221: Test FrameReader.set_limits updates limits | tests/test_cbor_io.py:239 |
| test222 | `test_222_frame_writer_set_limits` | TEST222: Test FrameWriter.set_limits updates limits | tests/test_cbor_io.py:251 |
| test223 | `test_223_handshake_host_sends_hello_first` | TEST223: Test handshake host sends HELLO first | tests/test_cbor_io.py:263 |
| test224 | `test_224_handshake_negotiates_to_minimum_limits` | TEST224: Test handshake negotiates to minimum limits | tests/test_cbor_io.py:299 |
| test225 | `test_225_handshake_function_full_handshake` | TEST225: Test handshake function performs full handshake | tests/test_cbor_io.py:335 |
| test226 | `test_226_handshake_accept_receives_first` | TEST226: Test handshake_accept receives first then sends | tests/test_cbor_io.py:365 |
| test227 | `test_227_handshake_fails_if_plugin_missing_manifest` | TEST227: Test handshake fails if plugin missing manifest | tests/test_cbor_io.py:396 |
| test228 | `test_228_read_frame_enforces_limit` | TEST228: Test read_frame enforces limit | tests/test_cbor_io.py:421 |
| test229 | `test_229_frame_with_zero_length_payload` | TEST229: Test frame with zero-length payload | tests/test_cbor_io.py:439 |
| test230 | `test_230_frame_roundtrip_preserves_fields` | TEST230: Test frame round-trip preserves all fields | tests/test_cbor_io.py:454 |
| test231 | `test_231_multiple_readers_on_same_stream` | TEST231: Test multiple readers on same stream | tests/test_cbor_io.py:476 |
| test232 | `test_232_writer_flushes_after_each_frame` | TEST232: Test writer flushes after each frame | tests/test_cbor_io.py:501 |
| test233 | `test_233_frame_encoding_preserves_binary_data` | TEST233: Test frame encoding preserves binary data | tests/test_cbor_io.py:514 |
| test234 | `test_234_handshake_with_very_small_limits` | TEST234: Test handshake with very small limits | tests/test_cbor_io.py:527 |
| test235 | `test_235_response_chunk` | TEST235: Test ResponseChunk stores payload, seq, offset, len, and eof fields correctly | tests/test_plugin_host_runtime.py:26 |
| test236 | `test_236_response_chunk_with_all_fields` | TEST236: Test ResponseChunk with all fields populated preserves offset, len, and eof | tests/test_plugin_host_runtime.py:43 |
| test237 | `test_237_plugin_response_single` | TEST237: Test PluginResponse::Single final_payload returns the single payload slice | tests/test_plugin_host_runtime.py:60 |
| test238 | `test_238_plugin_response_single_empty` | TEST238: Test PluginResponse::Single with empty payload returns empty slice and empty vec | tests/test_plugin_host_runtime.py:67 |
| test239 | `test_239_plugin_response_streaming` | TEST239: Test PluginResponse::Streaming concatenated joins all chunk payloads in order | tests/test_plugin_host_runtime.py:74 |
| test240 | `test_240_plugin_response_streaming_final_payload` | TEST240: Test PluginResponse::Streaming final_payload returns the last chunk's payload | tests/test_plugin_host_runtime.py:109 |
| test241 | `test_241_plugin_response_streaming_empty` | TEST241: Test PluginResponse::Streaming with empty chunks vec returns empty concatenation | tests/test_plugin_host_runtime.py:141 |
| test242 | `test_242_plugin_response_streaming_large` | TEST242: Test PluginResponse::Streaming concatenated capacity is pre-allocated correctly for large payloads | tests/test_plugin_host_runtime.py:148 |
| test243 | `test_243_async_host_error_variants` | TEST243: Test AsyncHostError variants display correct error messages | tests/test_plugin_host_runtime.py:184 |
| test244 | `test_244_async_host_error_from_cbor` | TEST244: Test AsyncHostError::from converts CborError to Cbor variant | tests/test_plugin_host_runtime.py:214 |
| test245 | `test_245_async_host_error_from_io` | TEST245: Test AsyncHostError::from converts io::Error to Io variant | tests/test_plugin_host_runtime.py:222 |
| test246 | `test_246_async_host_error_equality` | TEST246: Test AsyncHostError Clone implementation produces equal values | tests/test_plugin_host_runtime.py:229 |
| test247 | `test_247_response_chunk_copy` | TEST247: Test ResponseChunk Clone produces independent copy with same data | tests/test_plugin_host_runtime.py:240 |
| test248 | `test_248_register_and_find_handler` | TEST248: Test register_op and find_handler by exact cap URN | tests/test_plugin_runtime.py:73 |
| test249 | `test_249_raw_handler` | TEST249: Test register_op handler echoes bytes directly | tests/test_plugin_runtime.py:87 |
| test250 | `test_250_typed_handler_deserialization` | TEST250: Test Op handler collects input and processes it | tests/test_plugin_runtime.py:118 |
| test251 | `test_251_typed_handler_rejects_invalid_json` | TEST251: Test Op handler propagates errors through HandlerError | tests/test_plugin_runtime.py:151 |
| test252 | `test_252_find_handler_unknown_cap` | TEST252: Test find_handler returns None for unregistered cap URNs | tests/test_plugin_runtime.py:181 |
| test253 | `test_253_handler_is_send_sync` | TEST253: Test OpFactory can be used across threads (Send + Sync equivalent) | tests/test_plugin_runtime.py:187 |
| test254 | `test_254_no_peer_invoker` | TEST254: Test NoPeerInvoker always returns PeerRequest error regardless of arguments | tests/test_plugin_runtime.py:218 |
| test255 | `test_255_no_peer_invoker_with_arguments` | TEST255: Test NoPeerInvoker returns error even with valid arguments | tests/test_plugin_runtime.py:228 |
| test256 | `test_256_with_manifest_json` | TEST256: Test PluginRuntime::with_manifest_json stores manifest data and parses when valid | tests/test_plugin_runtime.py:237 |
| test257 | `test_257_new_with_invalid_json` | TEST257: Test PluginRuntime::new with invalid JSON still creates runtime (manifest is None) | tests/test_plugin_runtime.py:248 |
| test258 | `test_258_with_manifest_struct` | TEST258: Test PluginRuntime::with_manifest creates runtime with valid manifest data | tests/test_plugin_runtime.py:255 |
| test259 | `test_259_extract_effective_payload_non_cbor` | TEST259: Test extract_effective_payload with single stream matching cap in_spec | tests/test_plugin_runtime.py:264 |
| test260 | `test_260_extract_effective_payload_no_content_type` | TEST260: Test extract_effective_payload with wildcard in_spec accepts any stream | tests/test_plugin_runtime.py:274 |
| test261 | `test_261_extract_effective_payload_cbor_match` | TEST261: Test extract_effective_payload extracts matching stream by media URN | tests/test_plugin_runtime.py:283 |
| test262 | `test_262_extract_effective_payload_cbor_no_match` | TEST262: Test extract_effective_payload fails when no stream matches expected input | tests/test_plugin_runtime.py:300 |
| test263 | `test_263_extract_effective_payload_invalid_cbor` | TEST263: Test extract_effective_payload with empty streams returns error | tests/test_plugin_runtime.py:325 |
| test264 | `test_264_extract_effective_payload_cbor_not_array` | TEST264: Test extract_effective_payload with incomplete stream skips it | tests/test_plugin_runtime.py:337 |
| test265 | `test_265_extract_effective_payload_invalid_cap_urn` | TEST265: Test extract_effective_payload with invalid cap URN returns CapUrn error | tests/test_plugin_runtime.py:353 |
| test266 | `test_266_cli_stream_emitter_construction` | TEST266: Test CliStreamEmitter writes to stdout and stderr correctly (basic construction) | tests/test_plugin_runtime.py:364 |
| test268 | `test_268_runtime_error_display` | TEST268: Test RuntimeError variants display correct messages | tests/test_plugin_runtime.py:373 |
| test270 | `test_270_multiple_handlers` | TEST270: Test registering multiple Op handlers for different caps and finding each independently | tests/test_plugin_runtime.py:394 |
| test271 | `test_271_handler_replacement` | TEST271: Test Op handler replacing an existing registration for the same cap URN | tests/test_plugin_runtime.py:421 |
| test272 | `test_272_extract_effective_payload_multiple_args` | TEST272: Test extract_effective_payload with multiple streams selects the correct one | tests/test_plugin_runtime.py:452 |
| test273 | `test_273_extract_effective_payload_binary_value` | TEST273: Test extract_effective_payload with binary data in stream (not just text) | tests/test_plugin_runtime.py:475 |
| test274 | `test_274_cap_argument_value_new` | TEST274: Test CapArgumentValue::new stores media_urn and raw byte value | tests/test_caller.py:142 |
| test275 | `test_275_cap_argument_value_from_str` | TEST275: Test CapArgumentValue::from_str converts string to UTF-8 bytes | tests/test_caller.py:153 |
| test276 | `test_276_cap_argument_value_as_str_success` | TEST276: Test CapArgumentValue::value_as_str succeeds for UTF-8 data | tests/test_caller.py:165 |
| test277 | `test_277_cap_argument_value_as_str_fails_binary` | TEST277: Test CapArgumentValue::value_as_str fails for non-UTF-8 binary data | tests/test_caller.py:171 |
| test278 | `test_278_cap_argument_value_empty` | TEST278: Test CapArgumentValue::new with empty value stores empty vec | tests/test_caller.py:181 |
| test279 | `test_279_cap_argument_value_clone` | TEST279: Test CapArgumentValue Clone produces independent copy with same data | tests/test_caller.py:189 |
| test280 | `test_280_cap_argument_value_debug` | TEST280: Test CapArgumentValue Debug format includes media_urn and value | tests/test_caller.py:204 |
| test281 | `test_281_cap_argument_value_media_urn_types` | TEST281: Test CapArgumentValue::new accepts Into<String> for media_urn (String and &str) | tests/test_caller.py:222 |
| test282 | `test_282_cap_argument_value_unicode` | TEST282: Test CapArgumentValue::from_str with Unicode string preserves all characters | tests/test_caller.py:235 |
| test283 | `test_283_cap_argument_value_large_binary` | TEST283: Test CapArgumentValue with large binary payload preserves all bytes | tests/test_caller.py:245 |
| test284 | `test_284_handshake_host_plugin` | TEST284: Handshake exchanges HELLO frames, negotiates limits | tests/test_cbor_integration.py:52 |
| test285 | `test_285_request_response_simple` | TEST285: Simple request-response flow (REQ → END with payload) | tests/test_cbor_integration.py:87 |
| test286 | `test_286_streaming_chunks` | TEST286: Streaming response with multiple CHUNK frames | tests/test_cbor_integration.py:127 |
| test287 | `test_287_heartbeat_from_host` | TEST287: Host-initiated heartbeat handling | tests/test_cbor_integration.py:179 |
| test290 | `test_290_limits_negotiation` | TEST290: Limit negotiation picks minimum values | tests/test_cbor_integration.py:217 |
| test291 | `test_291_binary_payload_roundtrip` | TEST291: Binary payload roundtrip (all 256 byte values) | tests/test_cbor_integration.py:249 |
| test292 | `test_292_message_id_uniqueness` | TEST292: Sequential requests get distinct MessageIds | tests/test_cbor_integration.py:294 |
| test299 | `test_299_empty_payload_roundtrip` | TEST299: Empty payload request/response roundtrip | tests/test_cbor_integration.py:335 |
| test304 | `test_304_media_availability_output_constant` | TEST304: Test MEDIA_AVAILABILITY_OUTPUT constant parses as valid media URN with correct tags | tests/test_media_urn.py:249 |
| test305 | `test_305_media_path_output_constant` | TEST305: Test MEDIA_PATH_OUTPUT constant parses as valid media URN with correct tags | tests/test_media_urn.py:257 |
| test306 | `test_306_availability_and_path_output_distinct` | TEST306: Test MEDIA_AVAILABILITY_OUTPUT and MEDIA_PATH_OUTPUT are distinct URNs | tests/test_media_urn.py:265 |
| test307 | `test_307_model_availability_urn` | TEST307: Test model_availability_urn builds valid cap URN with correct op and media specs | tests/test_standard_caps.py:23 |
| test308 | `test_308_model_path_urn` | TEST308: Test model_path_urn builds valid cap URN with correct op and media specs | tests/test_standard_caps.py:31 |
| test309 | `test_309_model_availability_and_path_are_distinct` | TEST309: Test model_availability_urn and model_path_urn produce distinct URNs | tests/test_standard_caps.py:39 |
| test310 | `test_310_llm_conversation_urn_unconstrained` | TEST310: Test llm_conversation_urn uses unconstrained tag (not constrained) | tests/test_standard_caps.py:46 |
| test311 | `test_311_llm_conversation_urn_specs` | TEST311: Test llm_conversation_urn in/out specs match the expected media URNs semantically | tests/test_standard_caps.py:54 |
| test312 | `test_312_all_urn_builders_produce_valid_urns` | TEST312: Test all URN builders produce parseable cap URNs | tests/test_standard_caps.py:68 |
| test313 | `test_313_write_stream_chunked_reassembly` | TEST313: Test write_stream_chunked sends STREAM_START + CHUNK(s) + STREAM_END + END for payload larger than max_chunk, CHUNK frames + END frame, and reading them back reassembles the full original data | tests/test_cbor_io.py:549 |
| test314 | `test_314_exact_max_chunk_stream_chunked` | TEST314: Test payload exactly equal to max_chunk produces STREAM_START + 1 CHUNK + STREAM_END + END | tests/test_cbor_io.py:591 |
| test315 | `test_315_max_chunk_plus_one_splits_into_two_chunks` | TEST315: Test payload of max_chunk + 1 produces STREAM_START + 2 CHUNK + STREAM_END + END | tests/test_cbor_io.py:622 |
| test316 | `test_316_concatenated_vs_final_payload_divergence` | TEST316: Test that concatenated() returns full payload while final_payload() returns only last chunk | tests/test_plugin_host_runtime.py:265 |
| test317 | `test_317_chunking_data_integrity_3x` | TEST317: Test auto-chunking preserves data integrity across chunk boundaries for 3x max_chunk payload | tests/test_cbor_io.py:658 |
| test336 | `test_336_file_path_reads_file_passes_bytes` | TEST336: Single file-path arg with stdin source reads file and passes bytes to handler | tests/test_plugin_runtime.py:517 |
| test337 | `test_337_file_path_without_stdin_passes_string` | TEST337: file-path arg without stdin source passes path as string (no conversion) | tests/test_plugin_runtime.py:585 |
| test338 | `test_338_file_path_via_cli_flag` | TEST338: file-path arg reads file via --file CLI flag | tests/test_plugin_runtime.py:615 |
| test339 | `test_339_file_path_array_glob_expansion` | TEST339: file-path-array reads multiple files with glob pattern | tests/test_plugin_runtime.py:646 |
| test340 | `test_340_file_not_found_clear_error` | TEST340: File not found error provides clear message | tests/test_plugin_runtime.py:693 |
| test341 | `test_341_stdin_precedence_over_file_path` | TEST341: stdin takes precedence over file-path in source order | tests/test_plugin_runtime.py:726 |
| test342 | `test_342_file_path_position_zero_reads_first_arg` | TEST342: file-path with position 0 reads first positional arg as file | tests/test_plugin_runtime.py:761 |
| test343 | `test_343_non_file_path_args_unaffected` | TEST343: Non-file-path args are not affected by file reading | tests/test_plugin_runtime.py:793 |
| test344 | `test_344_file_path_array_invalid_json_fails` | TEST344: file-path-array with invalid JSON fails clearly | tests/test_plugin_runtime.py:824 |
| test345 | `test_345_file_path_array_one_file_missing_fails_hard` | TEST345: file-path-array with one file failing stops and reports error | tests/test_plugin_runtime.py:858 |
| test346 | `test_346_large_file_reads_successfully` | TEST346: Large file (1MB) reads successfully | tests/test_plugin_runtime.py:901 |
| test347 | `test_347_empty_file_reads_as_empty_bytes` | TEST347: Empty file reads as empty bytes | tests/test_plugin_runtime.py:936 |
| test348 | `test_348_file_path_conversion_respects_source_order` | TEST348: file-path conversion respects source order | tests/test_plugin_runtime.py:967 |
| test349 | `test_349_file_path_multiple_sources_fallback` | TEST349: file-path arg with multiple sources tries all in order | tests/test_plugin_runtime.py:1002 |
| test350 | `test_350_full_cli_mode_with_file_path_integration` | TEST350: Integration test - full CLI mode invocation with file-path | tests/test_plugin_runtime.py:1035 |
| test351 | `test_351_file_path_array_empty_array` | TEST351: file-path-array with empty array succeeds | tests/test_plugin_runtime.py:1107 |
| test352 | `test_352_file_permission_denied_clear_error` |  | tests/test_plugin_runtime.py:1139 |
| test353 | `test_353_cbor_payload_format_consistency` | TEST353: CBOR payload format matches between CLI and CBOR mode | tests/test_plugin_runtime.py:1182 |
| test354 | `test_354_glob_pattern_no_matches_empty_array` | TEST354: Glob pattern with no matches produces empty array | tests/test_plugin_runtime.py:1216 |
| test355 | `test_355_glob_pattern_skips_directories` | TEST355: Glob pattern skips directories | tests/test_plugin_runtime.py:1251 |
| test356 | `test_356_multiple_glob_patterns_combined` | TEST356: Multiple glob patterns combined | tests/test_plugin_runtime.py:1297 |
| test357 | `test_357_symlinks_followed` |  | tests/test_plugin_runtime.py:1346 |
| test358 | `test_358_binary_file_non_utf8` | TEST358: Binary file with non-UTF8 data reads correctly | tests/test_plugin_runtime.py:1383 |
| test359 | `test_359_invalid_glob_pattern_fails` | TEST359: Invalid glob pattern fails with clear error | tests/test_plugin_runtime.py:1417 |
| test360 | `test_360_extract_effective_payload_with_file_data` | TEST360: Extract effective payload handles file-path data correctly | tests/test_plugin_runtime.py:1453 |
| test361 | `test_361_cli_mode_file_path` | TEST361: CLI mode with file path - pass file path as command-line argument | tests/test_plugin_runtime.py:1495 |
| test362 | `test_362_cli_mode_piped_binary` | TEST362: CLI mode with binary piped in - pipe binary data via stdin  This test simulates real-world conditions: - Pure binary data piped to stdin (NOT CBOR) - CLI mode detected (command arg present) - Cap accepts stdin source - Binary is chunked on-the-fly and accumulated - Handler receives complete CBOR payload | tests/test_plugin_runtime.py:1539 |
| test363 | `test_363_cbor_mode_chunked_content` | TEST363: CBOR mode with chunked content - send file content streaming as chunks | tests/test_plugin_runtime.py:1586 |
| test364 | `test_364_cbor_mode_file_path` | TEST364: CBOR mode with file path - send file path in CBOR arguments (auto-conversion) | tests/test_plugin_runtime.py:1672 |
| test365 | `test_365_stream_start_frame` | TEST365: Frame::stream_start stores req_id, stream_id, media_urn | tests/test_cbor_frame.py:405 |
| test366 | `test_366_stream_end_frame` | TEST366: Frame::stream_end stores req_id, stream_id, chunk_count | tests/test_cbor_frame.py:420 |
| test367 | `test_367_stream_start_with_empty_stream_id` | TEST367: Frame::stream_start with empty stream_id still constructs | tests/test_cbor_frame.py:436 |
| test368 | `test_368_stream_start_with_empty_media_urn` | TEST368: Frame::stream_start with empty media_urn still constructs | tests/test_cbor_frame.py:447 |
| test389 | `test_389_stream_start_roundtrip` | TEST389: StreamStart encode/decode roundtrip preserves stream_id and media_urn | tests/test_cbor_io.py:692 |
| test390 | `test_390_stream_end_roundtrip` | TEST390: StreamEnd encode/decode roundtrip preserves stream_id, no media_urn | tests/test_cbor_io.py:708 |
| test395 | `test_395_build_payload_small` | TEST395: Small payload (< max_chunk) produces correct CBOR arguments | tests/test_plugin_runtime.py:1707 |
| test396 | `test_396_build_payload_large` | TEST396: Large payload (> max_chunk) accumulates across chunks correctly | tests/test_plugin_runtime.py:1739 |
| test397 | `test_397_build_payload_empty` | TEST397: Empty reader produces valid empty CBOR arguments | tests/test_plugin_runtime.py:1766 |
| test398 | `test_398_build_payload_io_error` | TEST398: IO error from reader propagates as error | tests/test_plugin_runtime.py:1797 |
| test399 | `test_399_relay_notify_discriminant_roundtrip` | TEST399: RelayNotify discriminant roundtrips through u8 conversion (value 10) | tests/test_cbor_frame.py:458 |
| test400 | `test_400_relay_state_discriminant_roundtrip` | TEST400: RelayState discriminant roundtrips through u8 conversion (value 11) | tests/test_cbor_frame.py:467 |
| test401 | `test_401_relay_notify_factory_and_accessors` | TEST401: relay_notify factory stores manifest and limits, accessors extract them correctly | tests/test_cbor_frame.py:476 |
| test402 | `test_402_relay_state_factory_and_payload` | TEST402: relay_state factory stores resource payload in payload field | tests/test_cbor_frame.py:504 |
| test403 | `test_403_frame_type_one_past_relay_state` | TEST403: FrameType::from_u8(12) returns None (one past RelayState) | tests/test_cbor_frame.py:515 |
| test404 | `test_404_slave_sends_relay_notify_on_connect` | TEST404: Slave sends RelayNotify on connect (initial_notify parameter) | tests/test_plugin_relay.py:22 |
| test405 | `test_405_master_reads_relay_notify` | TEST405: Master reads RelayNotify and extracts manifest + limits | tests/test_plugin_relay.py:56 |
| test406 | `test_406_slave_stores_relay_state` | TEST406: Slave stores RelayState from master (resource_state() returns payload) | tests/test_plugin_relay.py:84 |
| test407 | `test_407_protocol_frames_pass_through` | TEST407: Protocol frames pass through slave transparently (both directions) | tests/test_plugin_relay.py:121 |
| test408 | `test_408_relay_frames_not_forwarded` | TEST408: RelayNotify/RelayState are NOT forwarded through relay (intercepted) | tests/test_plugin_relay.py:210 |
| test409 | `test_409_slave_injects_relay_notify_midstream` | TEST409: Slave can inject RelayNotify mid-stream (cap change) | tests/test_plugin_relay.py:277 |
| test410 | `test_410_master_receives_updated_relay_notify` | TEST410: Master receives updated RelayNotify (cap change via read_frame) | tests/test_plugin_relay.py:326 |
| test411 | `test_411_socket_close_detection` | TEST411: Socket close detection (both directions) | tests/test_plugin_relay.py:387 |
| test412 | `test_412_bidirectional_concurrent_flow` | TEST412: Bidirectional concurrent frame flow through relay | tests/test_plugin_relay.py:421 |
| test413 | `test_413_register_plugin_adds_cap_table` | TEST413: RegisterPlugin adds entries to capTable | tests/test_plugin_host.py:81 |
| test414 | `test_414_capabilities_empty_initially` | TEST414: Capabilities() returns None when no plugins are running | tests/test_plugin_host.py:96 |
| test415 | `test_415_req_triggers_spawn` | TEST415: REQ for known cap triggers spawn (expect error for non-existent binary) | tests/test_plugin_host.py:104 |
| test416 | `test_416_attach_plugin_handshake` | TEST416: AttachPlugin performs HELLO handshake, extracts manifest, updates capabilities | tests/test_plugin_host.py:134 |
| test417 | `test_417_route_req_by_cap_urn` | TEST417: Route REQ to correct plugin by cap_urn (two plugins) | tests/test_plugin_host.py:161 |
| test418 | `test_418_route_continuation_by_req_id` | TEST418: Route STREAM_START/CHUNK/STREAM_END/END by req_id | tests/test_plugin_host.py:222 |
| test419 | `test_419_heartbeat_local_handling` | TEST419: Plugin HEARTBEAT handled locally (not forwarded to relay) | tests/test_plugin_host.py:281 |
| test420 | `test_420_plugin_frames_forwarded_to_relay` | TEST420: Plugin non-HELLO/non-HB frames forwarded to relay | tests/test_plugin_host.py:343 |
| test421 | `test_421_plugin_death_updates_caps` | TEST421: Plugin death updates capability list (removes dead plugin's caps) | tests/test_plugin_host.py:401 |
| test422 | `test_422_plugin_death_sends_err` | TEST422: Plugin death sends ERR for all pending requests | tests/test_plugin_host.py:442 |
| test423 | `test_423_multi_plugin_distinct_caps` | TEST423: Multiple plugins with distinct caps route independently | tests/test_plugin_host.py:490 |
| test424 | `test_424_concurrent_requests_same_plugin` | TEST424: Concurrent requests to same plugin handled independently | tests/test_plugin_host.py:571 |
| test425 | `test_425_find_plugin_for_cap_unknown` | TEST425: FindPluginForCap returns None for unknown cap | tests/test_plugin_host.py:638 |
| test426 | `test_426_single_master_req_response` | TEST426: Single master REQ/response routing | tests/test_relay_switch.py:28 |
| test427 | `test_427_multi_master_cap_routing` | TEST427: Multi-master cap routing | tests/test_relay_switch.py:77 |
| test428 | `test_428_unknown_cap_returns_error` | TEST428: Unknown cap returns error | tests/test_relay_switch.py:159 |
| test429 | `test_429_find_master_for_cap` | TEST429: Cap routing logic (find_master_for_cap) | tests/test_relay_switch.py:192 |
| test430 | `test_430_tie_breaking_same_cap_multiple_masters` | TEST430: Tie-breaking (same cap on multiple masters - first match wins, routing is consistent) | tests/test_relay_switch.py:238 |
| test431 | `test_431_continuation_frame_routing` | TEST431: Continuation frame routing (CHUNK, END follow REQ) | tests/test_relay_switch.py:312 |
| test432 | `test_432_empty_masters_list_error` | TEST432: Empty masters list returns error | tests/test_relay_switch.py:373 |
| test433 | `test_433_capability_aggregation_deduplicates` | TEST433: Capability aggregation deduplicates caps | tests/test_relay_switch.py:381 |
| test434 | `test_434_limits_negotiation_minimum` | TEST434: Limits negotiation takes minimum | tests/test_relay_switch.py:436 |
| test435 | `test_435_urn_matching_exact_and_accepts` | TEST435: URN matching (exact vs accepts()) | tests/test_relay_switch.py:477 |
| test479 | `test_479_custom_identity_overrides_default` | TEST479: Custom identity Op overrides auto-registered default | tests/test_plugin_runtime.py:1818 |
| test546 | `test_546_is_image` | TEST546: is_image returns true only when image marker tag is present | tests/test_media_urn.py:273 |
| test547 | `test_547_is_audio` | TEST547: is_audio returns true only when audio marker tag is present | tests/test_media_urn.py:285 |
| test548 | `test_548_is_video` | TEST548: is_video returns true only when video marker tag is present | tests/test_media_urn.py:296 |
| test549 | `test_549_is_numeric` | TEST549: is_numeric returns true only when numeric marker tag is present | tests/test_media_urn.py:306 |
| test550 | `test_550_is_bool` | TEST550: is_bool returns true only when bool marker tag is present | tests/test_media_urn.py:318 |
| test551 | `test_551_is_file_path` | TEST551: is_file_path returns true for scalar file-path, false for array | tests/test_media_urn.py:330 |
| test552 | `test_552_is_file_path_array` | TEST552: is_file_path_array returns true for list file-path, false for scalar | tests/test_media_urn.py:340 |
| test553 | `test_553_is_any_file_path` | TEST553: is_any_file_path returns true for both scalar and array file-path | tests/test_media_urn.py:349 |
| test555 | `test_555_with_tag_and_without_tag` | TEST555: with_tag adds a tag and without_tag removes it | tests/test_media_urn.py:358 |
| test556 | `test_556_image_media_urn_for_ext` | TEST556: image_media_urn_for_ext creates valid image media URN | tests/test_media_urn.py:374 |
| test557 | `test_557_audio_media_urn_for_ext` | TEST557: audio_media_urn_for_ext creates valid audio media URN | tests/test_media_urn.py:383 |
| test558 | `test_558_predicate_constant_consistency` | TEST558: predicates are consistent with constants | tests/test_media_urn.py:392 |
| test559 | `test_559_without_tag` | TEST559: without_tag removes tag, ignores in/out, case-insensitive for keys | tests/test_cap_urn.py:730 |
| test560 | `test_560_with_in_out_spec` | TEST560: with_in_spec and with_out_spec change direction specs | tests/test_cap_urn.py:754 |
| test561 | `test_561_in_out_media_urn` | TEST561: in_media_urn and out_media_urn parse direction specs into MediaUrn | tests/test_cap_urn.py:775 |
| test562 | `test_562_canonical_option` | TEST562: canonical_option returns None for None input, canonical string for Some | tests/test_cap_urn.py:795 |
| test563 | `test_563_find_all_matches` | TEST563: CapMatcher::find_all_matches returns all matching caps sorted by specificity | tests/test_cap_urn.py:814 |
| test564 | `test_564_are_compatible` | TEST564: CapMatcher::are_compatible detects bidirectional overlap | tests/test_cap_urn.py:832 |
| test565 | `test_565_tags_to_string` | TEST565: tags_to_string returns only tags portion without prefix | tests/test_cap_urn.py:855 |
| test566 | `test_566_with_tag_ignores_in_out` | TEST566: with_tag silently ignores in/out keys | tests/test_cap_urn.py:867 |
| test567 | `test_567_str_variants` | TEST567: conforms_to_str and accepts_str work with string arguments | tests/test_cap_urn.py:880 |
| test568 | `test_568_cap_graph_find_best_path` | TEST568: CapGraph::find_best_path returns highest-specificity path over shortest | tests/test_cap_matrix.py:647 |
| test569 | `test_569_cap_matrix_unregister_cap_set` | TEST569: unregister_cap_set removes a host and returns true, false if not found | tests/test_cap_matrix.py:338 |
| test570 | `test_570_cap_matrix_clear` | TEST570: clear removes all registered sets | tests/test_cap_matrix.py:355 |
| test571 | `test_571_cap_matrix_get_all_capabilities` | TEST571: get_all_capabilities returns caps from all hosts | tests/test_cap_matrix.py:303 |
| test572 | `test_572_cap_matrix_get_capabilities_for_host` | TEST572: get_capabilities_for_host returns caps for specific host, None for unknown | tests/test_cap_matrix.py:318 |
| test573 | `test_573_cap_matrix_iter_hosts_and_caps` | TEST573: iter_hosts_and_caps iterates all hosts with their capabilities | tests/test_cap_matrix.py:691 |
| test574 | `test_574_cap_block_remove_registry` | TEST574: CapBlock::remove_registry removes by name, returns the registry object; None for missing | tests/test_cap_matrix.py:609 |
| test575 | `test_575_cap_block_get_registry` | TEST575: CapBlock::get_registry returns registry by name, None for unknown | tests/test_cap_matrix.py:634 |
| test576 | `test_576_cap_matrix_get_host_names` | TEST576: CapBlock::get_registry_names returns names in insertion order | tests/test_cap_matrix.py:284 |
| test577 | `test_577_cap_graph_input_output_specs` | TEST577: CapGraph::get_input_specs and get_output_specs return correct sets | tests/test_cap_matrix.py:710 |
| test639 | `test_639_wildcard_empty_cap_defaults` | TEST639: cap: (empty) defaults to in=media:;out=media: | tests/test_cap_urn.py:905 |
| test640 | `test_640_wildcard_in_only_defaults_out` | TEST640: cap:in defaults out to media: | tests/test_cap_urn.py:913 |
| test641 | `test_641_wildcard_out_only_defaults_in` | TEST641: cap:out defaults in to media: | tests/test_cap_urn.py:920 |
| test642 | `test_642_wildcard_in_out_no_values` | TEST642: cap:in;out both become media: | tests/test_cap_urn.py:927 |
| test643 | `test_643_wildcard_explicit_asterisk` | TEST643: cap:in=*;out=* becomes media: | tests/test_cap_urn.py:934 |
| test644 | `test_644_wildcard_specific_in_wildcard_out` | TEST644: cap:in=media:;out=* has specific in, wildcard out | tests/test_cap_urn.py:941 |
| test645 | `test_645_wildcard_in_specific_out` | TEST645: cap:in=*;out=media:text has wildcard in, specific out | tests/test_cap_urn.py:948 |
| test646 | `test_646_wildcard_invalid_in_spec` | TEST646: cap:in=foo fails (invalid media URN) | tests/test_cap_urn.py:955 |
| test647 | `test_647_wildcard_invalid_out_spec` | TEST647: cap:in=media:;out=bar fails (invalid media URN) | tests/test_cap_urn.py:961 |
| test648 | `test_648_wildcard_accepts_specific` | TEST648: Wildcard in/out match specific caps | tests/test_cap_urn.py:967 |
| test649 | `test_649_wildcard_specificity_scoring` | TEST649: Specificity - wildcard has 0, specific has tag count | tests/test_cap_urn.py:976 |
| test650 | `test_650_wildcard_preserve_other_tags` | TEST650: cap:in;out;op=test preserves other tags | tests/test_cap_urn.py:985 |
| test651 | `test_651_wildcard_identity_forms_equivalent` | TEST651: All identity forms produce the same CapUrn | tests/test_cap_urn.py:993 |
| test652 | `test_652_wildcard_cap_identity_constant` | TEST652: CAP_IDENTITY constant matches identity caps regardless of string form | tests/test_cap_urn.py:1011 |
| test653 | `test_653_wildcard_identity_routing_isolation` | TEST653: Identity (no tags) does not match specific requests via routing | tests/test_cap_urn.py:1024 |
| test667 | `test_667_verify_chunk_checksum_detects_corruption` | TEST667: verify_chunk_checksum detects corrupted payload | tests/test_cbor_frame.py:521 |

---

*Generated from capns-py source tree*
*Total numbered tests: 398*
