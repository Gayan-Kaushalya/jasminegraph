/*
//@HEADER
// *****************************************************************************
//
//  XtraPuLP: Xtreme-Scale Graph Partitioning using Label Propagation
//              Copyright (2016) Sandia Corporation
//
// Under the terms of Contract DE-AC04-94AL85000 with Sandia Corporation,
// the U.S. Government retains certain rights in this software.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the Corporation nor the names of the
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY SANDIA CORPORATION "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL SANDIA CORPORATION OR THE
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Questions?  Contact  George M. Slota   (gmslota@sandia.gov)
//                      Siva Rajamanickam (srajama@sandia.gov)
//                      Kamesh Madduri    (madduri@cse.psu.edu)
//
// *****************************************************************************
//@HEADER
*/

#include <mpi.h>
#include <omp.h>
#include <cstdlib>
#include <cstdint>
#include <cassert>
#include <cstdio>

#include "xtrapulp.h"
#include "dist_graph.h"
#include "util.h"

extern int procid, nprocs;
extern bool verbose, debug, verify;

int repart(dist_graph_t *g, int32_t* local_parts)
{
  MPI_Barrier(MPI_COMM_WORLD);
  double elt = timer();

  int32_t* sendcounts = (int32_t*)malloc(nprocs*sizeof(int32_t));
  assert(sendcounts != NULL);  
  int32_t* recvcounts = (int32_t*)malloc(nprocs*sizeof(int32_t));
  assert(recvcounts != NULL);
  for (int32_t i = 0; i < nprocs; ++i)
  {
    sendcounts[i] = 0;
    recvcounts[i] = 0;
  }
  for (uint64_t i = 0; i < g->n_local; ++i)
  {
    int32_t rank = local_parts[i];
    ++sendcounts[rank];
  }

  MPI_Alltoall(sendcounts, 1, MPI_INT32_T, 
    recvcounts, 1, MPI_INT32_T, MPI_COMM_WORLD);
   
  int32_t* sdispls = (int32_t*)malloc(nprocs*sizeof(int32_t));
  assert(sdispls != NULL);  
  int32_t* sdispls_cpy = (int32_t*)malloc(nprocs*sizeof(int32_t));
  assert(sdispls_cpy != NULL);
  int32_t* rdispls = (int32_t*)malloc(nprocs*sizeof(int32_t));
  assert(rdispls != NULL);   

  sdispls[0] = 0;
  sdispls_cpy[0] = 0;
  rdispls[0] = 0;
  for (int32_t i = 0; i < nprocs-1; ++i)
  {
    sdispls[i+1] = sdispls[i] + sendcounts[i];
    sdispls_cpy[i+1] = sdispls[i+1];
    rdispls[i+1] = rdispls[i] + recvcounts[i];
  }
  int32_t total_send_deg = sdispls[nprocs-1] + sendcounts[nprocs-1];
  int32_t total_recv_deg = rdispls[nprocs-1] + recvcounts[nprocs-1];
  printf("%d totals %d %d %lu\n", procid, total_send_deg, total_recv_deg, (unsigned long)g->n_local);
  assert((uint64_t)total_send_deg == g->n_local);

  uint64_t* sendbuf_vids;
  uint64_t* sendbuf_deg_out;
  uint64_t* recvbuf_vids;
  uint64_t* recvbuf_deg_out;
  sendbuf_vids = (uint64_t*)malloc(total_send_deg*sizeof(uint64_t));
  assert(sendbuf_vids != NULL);   
  sendbuf_deg_out = (uint64_t*)malloc(total_send_deg*sizeof(uint64_t));
  assert(sendbuf_deg_out != NULL);   
  recvbuf_vids = (uint64_t*)malloc(total_recv_deg*sizeof(uint64_t));
  assert(recvbuf_vids != NULL);  
  recvbuf_deg_out = (uint64_t*)malloc(total_recv_deg*sizeof(uint64_t));
  assert(recvbuf_deg_out != NULL);   
  for (uint64_t i = 0; i < g->n_local; ++i)
  {    
    int32_t rank = local_parts[i];
    int32_t snd_index = sdispls_cpy[rank]++;
    sendbuf_vids[snd_index] = g->local_unmap[i];
    sendbuf_deg_out[snd_index] = out_degree(g, i);
  }

  MPI_Alltoallv(sendbuf_vids, sendcounts, sdispls, MPI_UINT64_T, 
    recvbuf_vids, recvcounts, rdispls, MPI_UINT64_T, MPI_COMM_WORLD);
  MPI_Alltoallv(sendbuf_deg_out, sendcounts, sdispls, MPI_UINT64_T, 
    recvbuf_deg_out, recvcounts, rdispls, MPI_UINT64_T, MPI_COMM_WORLD);
  free(sendbuf_vids);
  free(sendbuf_deg_out);

  for (int32_t i = 0; i < nprocs; ++i)
  {
    sendcounts[i] = 0;
    recvcounts[i] = 0;
  }
  for (uint64_t i = 0; i < g->n_local; ++i)
  {
    int32_t rank = local_parts[i];
    sendcounts[rank] += (int32_t)out_degree(g, i);
  }

  MPI_Alltoall(sendcounts, 1, MPI_INT32_T, 
    recvcounts, 1, MPI_INT32_T, MPI_COMM_WORLD);

  sdispls[0] = 0;
  sdispls_cpy[0] = 0;
  rdispls[0] = 0;
  for (int32_t i = 0; i < nprocs-1; ++i)
  {
    sdispls[i+1] = sdispls[i] + sendcounts[i];
    sdispls_cpy[i+1] = sdispls[i+1];
    rdispls[i+1] = rdispls[i] + recvcounts[i];
  }
  uint64_t total_send_out = (uint64_t)sdispls[nprocs-1] + (uint64_t)sendcounts[nprocs-1];
  uint64_t total_recv_out = (uint64_t)rdispls[nprocs-1] + (uint64_t)recvcounts[nprocs-1];
  assert(total_send_out == (uint64_t)g->m_local);

  uint64_t* sendbuf_e_out; 
  uint64_t* recvbuf_e_out; 
  sendbuf_e_out = (uint64_t*)malloc(total_send_out*sizeof(uint64_t));
  assert(sendbuf_e_out != NULL);
  recvbuf_e_out = (uint64_t*)malloc(total_recv_out*sizeof(uint64_t));
  assert(recvbuf_e_out != NULL);

  uint64_t counter = 0;
  for (uint64_t i = 0; i < g->n_local; ++i)
  {
    uint64_t deg = out_degree(g, i);
    uint64_t* outs = out_vertices(g, i);
    int32_t rank = local_parts[i];
    int32_t snd_index = sdispls_cpy[rank];
    sdispls_cpy[rank] += (int32_t)deg;
    for (uint64_t j = 0; j < deg; ++j)
    {
      assert(outs[j] < g->n_total);
      uint64_t out;
      if (outs[j] < g->n_local)
        out = g->local_unmap[outs[j]];
      else
        out = g->ghost_unmap[outs[j]-g->n_local];
      sendbuf_e_out[snd_index++] = out;
      counter++;
      assert(out < g->n);
    }
  }
  assert(counter == (uint64_t)g->m_local);

  MPI_Alltoallv(sendbuf_e_out, sendcounts, sdispls, MPI_UINT64_T, 
    recvbuf_e_out, recvcounts, rdispls, MPI_UINT64_T, MPI_COMM_WORLD);
  free(sendbuf_e_out);
  free(g->out_edges);
  free(g->out_degree_list);
  g->out_edges = recvbuf_e_out;
  g->m_local = (int64_t)total_recv_out;
  g->out_degree_list = (uint64_t*)malloc((total_recv_deg+1)*sizeof(uint64_t));
  g->out_degree_list[0] = 0;
  for (int32_t i = 0; i < total_recv_deg; ++i)
    g->out_degree_list[i+1] = g->out_degree_list[i] + recvbuf_deg_out[i];
  printf("BLAH %d %lu %lu\n", procid, 
    (unsigned long)g->out_degree_list[total_recv_deg], 
    (unsigned long)g->m_local);
  assert(g->out_degree_list[total_recv_deg] == (uint64_t)g->m_local);
  free(recvbuf_deg_out);

  free(g->local_unmap);
  g->local_unmap = (uint64_t*)malloc(total_recv_deg*sizeof(uint64_t));
  for (int32_t i = 0; i < total_recv_deg; ++i)
    g->local_unmap[i] = recvbuf_vids[i];
  free(recvbuf_vids);

  g->n_local = total_recv_deg;

  elt = timer() - elt;

  printf("%d done repart %lu %lu, %9.6lf (s)\n", procid, 
    (unsigned long)g->n_local, (unsigned long)g->m_local, elt);

  free(sendcounts);
  free(recvcounts);
  free(sdispls);
  free(sdispls_cpy);
  free(rdispls);

  return 0;
}


int get_ghost_tasks(dist_graph_t *g)
{
  double elt = timer();

  int64_t n_local_max = g->n_local;
  int32_t cur_size;
  MPI_Allreduce(MPI_IN_PLACE, &n_local_max, 1,
    MPI_INT64_T, MPI_MAX, MPI_COMM_WORLD);
  uint64_t* buf = (uint64_t*)malloc(n_local_max*sizeof(uint64_t));
  uint64_t* tmp_buf;

  for (int32_t p = 0; p < nprocs; ++p)  
  {
    if (p == procid)
    {
      printf("%d my time to shine\n", procid);
      tmp_buf = g->local_unmap;
      cur_size = (int32_t)g->n_local;
    }
    else
      tmp_buf = buf;

    MPI_Bcast(&cur_size, 1, MPI_INT32_T, p, MPI_COMM_WORLD);
    MPI_Bcast(tmp_buf, cur_size, MPI_UINT64_T, p, MPI_COMM_WORLD);

    if (p != procid)
    {
#pragma omp parallel for
      for (uint64_t i = 0; i < (uint64_t)cur_size; ++i)
      {
#if NO_HASH
        uint64_t val = g->mapper[buf[i]];
#else 
        uint64_t val = get_value(g->map, buf[i]);
#endif
        if (val != NULL_KEY)
          g->ghost_tasks[val-g->n_local] = p;
      }
    }
  }

  for (uint64_t i = 0; i < g->n_ghost; ++i)
    if (g->ghost_tasks[i] >= (uint64_t)nprocs)
      printf("EROR %d -- %lu, %lu %lu\n", procid, 
        (unsigned long)i, (unsigned long)g->ghost_unmap[i], 
        (unsigned long)g->ghost_tasks[i]);

  free(buf);

  elt = timer() - elt;

  printf("%d done getting ghost tasks %9.6lf (s)\n", procid, elt);  

  return 0;
}
