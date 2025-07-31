static struct pcpu_chunk *pcpu_alloc_chunk(void)
{
	struct pcpu_chunk *chunk;

	chunk = pcpu_mem_zalloc(pcpu_chunk_struct_size);
	if (!chunk)
		return NULL;

	chunk->map = pcpu_mem_zalloc(PCPU_DFL_MAP_ALLOC *
						sizeof(chunk->map[0]));
	if (!chunk->map) {
		pcpu_mem_free(chunk);
		return NULL;
	}

	chunk->map_alloc = PCPU_DFL_MAP_ALLOC;
	chunk->map[0] = 0;
	chunk->map[1] = pcpu_unit_size | 1;
	chunk->map_used = 1;

	INIT_LIST_HEAD(&chunk->list);
	INIT_WORK(&chunk->map_extend_work, pcpu_map_extend_workfn);
	chunk->free_size = pcpu_unit_size;
	chunk->contig_hint = pcpu_unit_size;

	return chunk;
}