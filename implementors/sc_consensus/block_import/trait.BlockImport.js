(function() {var implementors = {
"centrifuge_chain":[["impl&lt;B, I, C&gt; BlockImport&lt;B&gt; for <a class=\"struct\" href=\"centrifuge_chain/service/evm/struct.BlockImport.html\" title=\"struct centrifuge_chain::service::evm::BlockImport\">BlockImport</a>&lt;B, I, C&gt;<span class=\"where fmt-newline\">where<br>    B: BlockT,<br>    &lt;B::Header as HeaderT&gt;::Number: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialOrd.html\" title=\"trait core::cmp::PartialOrd\">PartialOrd</a>,<br>    I: BlockImportT&lt;B, Transaction = TransactionFor&lt;C, B&gt;&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,<br>    I::Error: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;ConsensusError&gt;,<br>    C: ProvideRuntimeApi&lt;B&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + HeaderBackend&lt;B&gt; + AuxStore + BlockOf,<br>    C::Api: EthereumRuntimeRPCApi&lt;B&gt; + BlockBuilderApi&lt;B&gt;,</span>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()