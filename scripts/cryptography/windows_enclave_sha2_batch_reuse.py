"""Replay prior primitive reviews before exact, explicitly scoped batch reuse."""
import windows_enclave_kmac_chains as c
import windows_enclave_kmac_reuse as reuse
import windows_enclave_sha2_primitives as scalar
import windows_enclave_sha_ni_owner as accelerated

require,digest=c.require,c.digest


def prior(base,lane):
    route='sha2/mod.rs::'+('open' if lane=='scalar' else 'open_sha_ni')
    row=next(r for r in c.shared.catalog(c.shared.CATALOG.read_bytes()) if r['route']==route)
    profile=next(r for r in c.w.specification(c.w.SPEC.read_bytes())['profiles'] if r['route']==route)
    directory=(base/row['object']).parent
    native=(base/row['object']).read_bytes();image=(base/row['image']).read_bytes()
    require(digest(native)==row['object_sha256'] and digest(image)==row['sha256'],'prior C/image identities')
    archive=(directory/'normal_rust.lib').read_bytes()
    data=c.w.archive.members(archive)[profile['member']]
    ir=(directory/'normal_rust.ll').read_bytes()
    if lane=='scalar':
        require(digest(archive)==scalar.entry.ARCHIVE,'prior scalar archive identity')
        report=scalar.inspect(data,native,image,
            (base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes(),ir)
    else: report=accelerated.inspect(base)
    require(digest(data)==report['object_sha256'],'replayed prior object identity')
    return row,data,ir.decode(),report


def exact(current,previous,ir,old_ir,names):
    result={}
    for now,old in names.items():
        require(now in current and old in previous,'all explicitly reused bodies present')
        require(current[now]==previous[old],'complete reused body, references and extent kind')
        abi=reuse.abi(ir,now);before=reuse.abi(old_ir,old).replace('@'+old+'(','@'+now+'(')
        require(abi==before,'exact reused resolved LLVM ABI')
        result[now]=dict(prior_name=old,abi_sha256=digest(abi.encode()))
    return result


def local_tables(data,name):
    rows,symbols,selected,_,refs=c.obj.select(data,name);result=[]
    indices={r['symbol_index'] for r in refs if r['symbol']=='.rdata'}
    for index in sorted(indices):
        symbol=symbols[index];row=rows[symbol['section']-1]
        require(symbol['value']==0 and row['flags'] & 0xe0000000==0x40000000,'readonly local table')
        relocs=c.obj.relocations(data,row,symbols)
        for ref in relocs.values():
            target=symbols[ref['symbol']]
            require(ref['kind']==4 and target['section']==selected['section'] and
                target['value']==0 and target['name']=='.text','table targets current function only')
        result.append(dict(raw=row['code'].hex(),relative_relocation_offsets=sorted(relocs)))
    return result


def inspect(base,lane,data,functions,ir):
    require(lane in ('scalar','sha_ni'),'sequential primitive reuse only')
    row,old_data,old_ir,report=prior(base,lane)
    previous=c.previous.inventory(old_data)
    if lane=='scalar':
        names={n:n for n in scalar.shapes.PINS}
        wipe=c.shapes.one(previous,r'HardenedSha2Owner4wipe$')
        names.update({wipe:wipe,c.shapes.ZERO:c.shapes.ZERO})
        finish=c.shapes.one(functions,r'state.*State6finish$')
        names[finish]=scalar.state.FINISH
        now=local_tables(data,finish);before=local_tables(old_data,scalar.state.FINISH)
        require(now==before and len(now)==1,'all scalar finalizer dispatch tables retained')
        tables=dict(function=finish,sha256=digest(c.shared.encoded(now)),
            source='same State implementation; seven identities and same output/bit-string ABI')
    else:
        names={n:n for n in accelerated.engine.shapes.NAMES}
        for n in (accelerated.life.SCRATCH,accelerated.life.wiping.WIPE,
                  c.shapes.ZERO,accelerated.state.COPY,accelerated.state.BYTES,accelerated.shapes.PREDICATE):
            names[n]=n
        tables=None
    matched=exact(functions,previous,ir,old_ir,names)
    require(len(matched)==(15 if lane=='scalar' else 14),'exact explicitly reviewed reuse population')
    return dict(prior_route=row['route'],prior_image_sha256=report['image_sha256'],
        prior_object_sha256=report['object_sha256'],prior_semantic_review_replayed=True,
        exact_helper_contracts=matched,renamed_scalar_finalizer_tables=tables,
        current_image_references_rebound_by_parent=True,
        batch_specific_caller_preconditions_pending=True,unlisted_equal_bodies_implicitly_qualified=False)
