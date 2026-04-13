(* ===================================================================== *)
(* DpoRmdir.v — DPO rule RMDIR + invariant preservation proofs          *)
(*                                                                       *)
(* Corresponds to:                                                       *)
(*   TLA+:  Rmdir(parent_dir, name) in sotfs_graph.tla                  *)
(*   Rust:  rmdir() in sotfs-ops/src/lib.rs                              *)
(*                                                                       *)
(* The rule removes a directory:                                         *)
(*   - Removes the entry edge (parent_dir, target_ino, name)            *)
(*   - Removes the "." edge (target_dir, target_ino, dot_name)          *)
(*   - Removes the ".." edge (target_dir, parent_ino, dotdot_name)      *)
(*   - Removes the DirRec for target_dir                                 *)
(*   - Removes the InodeRec for target_ino                               *)
(*                                                                       *)
(* Precondition: the directory is empty (no user-name edges from it).    *)
(* ===================================================================== *)

Require Import Coq.Arith.Arith.
Require Import Coq.Lists.List.
Require Import Coq.Bool.Bool.
Require Import Lia.
Import ListNotations.

Require Import SotfsGraph.

(* ===================================================================== *)
(* 1. List removal helpers                                               *)
(* ===================================================================== *)

Definition remove_inode (id : InodeId) (inodes : list InodeRec) : list InodeRec :=
  filter (fun ir => negb (Nat.eqb (ir_id ir) id)) inodes.

Definition remove_dir (id : DirId) (dirs : list DirRec) : list DirRec :=
  filter (fun dr => negb (Nat.eqb (dr_id dr) id)) dirs.

Definition remove_three_edges (e1 e2 e3 : ContainsEdge) (edges : list ContainsEdge)
  : list ContainsEdge :=
  filter (fun e => negb (ce_eqb e e1) && negb (ce_eqb e e2) && negb (ce_eqb e e3))
    edges.

(* ===================================================================== *)
(* 2. Preconditions                                                      *)
(* ===================================================================== *)

Record RmdirPre (g : Graph) (parent_dir : DirId) (name : Name)
  (target_ino : InodeId) (target_dir : DirId) (parent_ino : InodeId)
  : Prop := {
  rmp_dir_exists    : dir_exists g parent_dir;
  rmp_user_name     : is_user_name name;
  rmp_entry_exists  : In (mkContains parent_dir target_ino name) (g_edges g);
  rmp_dot_exists    : In (mkContains target_dir target_ino dot_name) (g_edges g);
  rmp_dotdot_exists : In (mkContains target_dir parent_ino dotdot_name) (g_edges g);
  rmp_is_directory  : forall ir, find_inode g target_ino = Some ir ->
                         ir_vtype ir = DirectoryType;
  rmp_target_exists : inode_exists g target_ino;
  rmp_tdir_exists   : dir_exists g target_dir;
  rmp_tdir_link     : find_dir g target_dir = Some (mkDir target_dir target_ino);
  rmp_empty         : forall e, In e (g_edges g) ->
                        ce_dir e = target_dir ->
                        is_user_name (ce_name e) -> False;
  rmp_parent_ino    : inode_exists g parent_ino;
  rmp_target_ne     : target_dir <> parent_dir;
  rmp_ino_ne        : target_ino <> parent_ino;
}.

(* ===================================================================== *)
(* 3. The rmdir function                                                 *)
(* ===================================================================== *)

Definition rmdir (g : Graph) (parent_dir : DirId) (name : Name)
  (target_ino : InodeId) (target_dir : DirId) (parent_ino : InodeId) : Graph :=
  let entry_edge := mkContains parent_dir target_ino name in
  let dot_edge := mkContains target_dir target_ino dot_name in
  let dotdot_edge := mkContains target_dir parent_ino dotdot_name in
  {| g_inodes := remove_inode target_ino (g_inodes g);
     g_dirs   := remove_dir target_dir (g_dirs g);
     g_edges  := remove_three_edges entry_edge dot_edge dotdot_edge (g_edges g);
  |}.

(* ===================================================================== *)
(* 4. Auxiliary lemmas                                                   *)
(* ===================================================================== *)

Lemma remove_inode_preserves :
  forall id inodes ir,
    In ir inodes -> ir_id ir <> id -> In ir (remove_inode id inodes).
Proof.
  intros id inodes ir Hin Hneq.
  unfold remove_inode. apply filter_In. split.
  - exact Hin.
  - simpl. apply Nat.eqb_neq in Hneq. rewrite Hneq. reflexivity.
Qed.

Lemma remove_inode_subset :
  forall id inodes ir,
    In ir (remove_inode id inodes) -> In ir inodes.
Proof.
  intros. unfold remove_inode in H. apply filter_In in H. tauto.
Qed.

Lemma remove_inode_not_in :
  forall id inodes ir,
    In ir (remove_inode id inodes) -> ir_id ir <> id.
Proof.
  intros id inodes ir Hin.
  unfold remove_inode in Hin. apply filter_In in Hin.
  destruct Hin as [_ Hf]. simpl in Hf.
  destruct (Nat.eqb (ir_id ir) id) eqn:Heq.
  - discriminate.
  - apply Nat.eqb_neq. exact Heq.
Qed.

Lemma remove_dir_preserves :
  forall id dirs dr,
    In dr dirs -> dr_id dr <> id -> In dr (remove_dir id dirs).
Proof.
  intros. unfold remove_dir. apply filter_In. split.
  - exact H.
  - simpl. apply Nat.eqb_neq in H0. rewrite H0. reflexivity.
Qed.

Lemma remove_dir_subset :
  forall id dirs dr,
    In dr (remove_dir id dirs) -> In dr dirs.
Proof.
  intros. unfold remove_dir in H. apply filter_In in H. tauto.
Qed.

Lemma remove_three_edges_subset :
  forall e1 e2 e3 edges e,
    In e (remove_three_edges e1 e2 e3 edges) -> In e edges.
Proof.
  intros. unfold remove_three_edges in H. apply filter_In in H. tauto.
Qed.

Lemma remove_three_edges_not_e1 :
  forall e1 e2 e3 edges e,
    In e (remove_three_edges e1 e2 e3 edges) -> e <> e1.
Proof.
  intros. unfold remove_three_edges in H. apply filter_In in H.
  destruct H as [_ Hf].
  intro Heq. subst e.
  rewrite ce_eqb_refl in Hf. simpl in Hf. discriminate.
Qed.

Lemma remove_three_edges_not_e2 :
  forall e1 e2 e3 edges e,
    In e (remove_three_edges e1 e2 e3 edges) -> e <> e2.
Proof.
  intros. unfold remove_three_edges in H. apply filter_In in H.
  destruct H as [_ Hf].
  intro Heq. subst e.
  rewrite ce_eqb_refl in Hf. simpl in Hf.
  destruct (ce_eqb e2 e1); simpl in Hf; discriminate.
Qed.

Lemma remove_three_edges_not_e3 :
  forall e1 e2 e3 edges e,
    In e (remove_three_edges e1 e2 e3 edges) -> e <> e3.
Proof.
  intros. unfold remove_three_edges in H. apply filter_In in H.
  destruct H as [_ Hf].
  intro Heq. subst e.
  rewrite ce_eqb_refl in Hf.
  destruct (ce_eqb e3 e1); destruct (ce_eqb e3 e2); simpl in Hf; discriminate.
Qed.

Lemma remove_inode_NoDup :
  forall id inodes,
    NoDup (map ir_id inodes) ->
    NoDup (map ir_id (remove_inode id inodes)).
Proof.
  intros id inodes. unfold remove_inode.
  induction inodes as [|h t IH]; intro Hnd.
  - simpl. constructor.
  - simpl. destruct (Nat.eqb (ir_id h) id) eqn:Heq.
    + simpl. apply IH. inversion Hnd. exact H2.
    + simpl. constructor.
      * inversion Hnd. intro Hin.
        apply in_map_iff in Hin. destruct Hin as [x [Hxid Hxin]].
        apply filter_In in Hxin. destruct Hxin as [Hxin _].
        apply H1. rewrite Hxid. apply in_map. exact Hxin.
      * apply IH. inversion Hnd. exact H2.
Qed.

Lemma remove_dir_NoDup :
  forall id dirs,
    NoDup (map dr_id dirs) ->
    NoDup (map dr_id (remove_dir id dirs)).
Proof.
  intros id dirs. unfold remove_dir.
  induction dirs as [|h t IH]; intro Hnd.
  - simpl. constructor.
  - simpl. destruct (Nat.eqb (dr_id h) id) eqn:Heq.
    + simpl. apply IH. inversion Hnd. exact H2.
    + simpl. constructor.
      * inversion Hnd. intro Hin.
        apply in_map_iff in Hin. destruct Hin as [x [Hxid Hxin]].
        apply filter_In in Hxin. destruct Hxin as [Hxin _].
        apply H1. rewrite Hxid. apply in_map. exact Hxin.
      * apply IH. inversion Hnd. exact H2.
Qed.

(* ===================================================================== *)
(* 5. THEOREM: rmdir preserves TypeInvariant                             *)
(* ===================================================================== *)

Theorem rmdir_preserves_TypeInvariant :
  forall g pd name ti td pi,
    WellFormed g ->
    RmdirPre g pd name ti td pi ->
    TypeInvariant (rmdir g pd name ti td pi).
Proof.
  intros g pd name ti td pi HWF Hpre.
  destruct HWF as [HTI [HLC [HUN [HND HNC]]]].
  destruct HTI as [Hedge [HnodupI HnodupD]].
  destruct Hpre as [Hdir Huser He Hdot Hddot Hisdir Htgt Htd Htdlink Hempty Hpi Htne Hine].
  unfold TypeInvariant. repeat split.
  - (* endpoints exist *)
    intros e Hin.
    assert (Hin_orig := remove_three_edges_subset _ _ _ _ _ Hin).
    destruct (HND e Hin_orig) as [Hd Hi]. split.
    + (* dir_exists in rmdir graph *)
      unfold dir_exists, dir_ids, rmdir. simpl.
      apply in_map_iff.
      assert (Hce_dir_ne : ce_dir e <> td).
      { intro Habs.
        (* If ce_dir e = td, then e is from target_dir.
           We know e is not entry/dot/dotdot (removed).
           So e must be a user-name edge from td. But directory is empty. *)
        assert (Hne1 := remove_three_edges_not_e1 _ _ _ _ _ Hin).
        assert (Hne2 := remove_three_edges_not_e2 _ _ _ _ _ Hin).
        assert (Hne3 := remove_three_edges_not_e3 _ _ _ _ _ Hin).
        (* e has ce_dir = td, and is not dot or dotdot edge.
           If ce_name e is user_name, contradiction with Hempty.
           Otherwise ce_name must be dot_name or dotdot_name.
           If dot_name: e = (td, ce_ino e, 0). UniqueNamesPerDir says
           this equals Hdot = (td, ti, 0). So e = dot_edge. Contradiction.
           If dotdot_name: similar, e = dotdot_edge. *)
        destruct (Nat.eq_dec (ce_name e) dot_name) as [Hdname | Hndname].
        - (* ce_name e = dot_name *)
          apply Hne2.
          assert (Heq := HUN e (mkContains td ti dot_name) Hin_orig Hdot).
          rewrite Habs in Heq. specialize (Heq eq_refl Hdname).
          exact Heq.
        - destruct (Nat.eq_dec (ce_name e) dotdot_name) as [Hddname | Hnddname].
          + (* ce_name e = dotdot_name *)
            apply Hne3.
            assert (Heq := HUN e (mkContains td pi dotdot_name) Hin_orig Hddot).
            rewrite Habs in Heq. specialize (Heq eq_refl Hddname).
            exact Heq.
          + (* ce_name e is a user name *)
            apply (Hempty e Hin_orig Habs).
            unfold is_user_name, dot_name, dotdot_name in *.
            destruct (ce_name e) as [| [|n]]; try contradiction.
            * exfalso. apply Hndname. reflexivity.
            * exfalso. apply Hnddname. reflexivity.
            * lia. }
      unfold dir_exists, dir_ids in Hd.
      apply in_map_iff in Hd. destruct Hd as [dr [Hdr_id Hdr_in]].
      exists dr. split.
      * exact Hdr_id.
      * apply remove_dir_preserves.
        { exact Hdr_in. }
        { rewrite <- Hdr_id. exact Hce_dir_ne. }
    + (* inode_exists in rmdir graph *)
      unfold inode_exists, inode_ids, rmdir. simpl.
      assert (Hce_ino_ne : ce_ino e <> ti).
      { intro Habs.
        (* If ce_ino e = ti and ce_dir e <> td, then e targets ti from
           another directory. But we need to check if this is the entry edge.
           The entry edge is (pd, ti, name). If e = entry, it was removed. *)
        assert (Hne1 := remove_three_edges_not_e1 _ _ _ _ _ Hin).
        (* If e = (pd, ti, name), then e = entry_edge. Contradiction. *)
        (* But e might target ti from a different dir or with a different name.
           That's OK — ti has link_count = 2, meaning two incoming non-dotdot
           edges. Those are (pd, ti, name) and (td, ti, dot).
           - (pd, ti, name) is removed (entry edge)
           - (td, ti, dot) is removed (dot edge)
           Any other edge targeting ti would mean link_count > 2.
           But link_count = 2 for a directory with exactly these two edges.
           However, we don't have link_count=2 in our preconditions directly.
           Instead, we use a counting argument.

           For this proof, we take a simpler approach: we know that e survives
           removal, so e ≠ entry and e ≠ dot. If ce_ino e = ti, then
           e is an incoming edge to ti with some name. Since e ≠ (pd,ti,name)
           and e ≠ (td,ti,dot), the edge (ce_dir e, ti, ce_name e) is
           in the old graph and targets ti. This is fine — we just need
           ti to still be in inodes. But we're removing ti!

           Actually, this IS a problem. After rmdir, ti is removed.
           Any surviving edge targeting ti would dangle. So we must show
           no such edge survives. This is guaranteed by LinkCountConsistent:
           ti has link_count = |incoming non-dotdot edges|. The entry edge
           and dot edge are the only two non-dotdot edges (link_count=2).
           After removing both, there are no remaining non-dotdot edges to ti.
           Any dotdot edge to ti would have name = dotdot_name. But directories
           point ".." to their PARENT, and ti is a leaf directory.

           Actually we should just strengthen the precondition or prove this
           as a lemma. For now, we use the fact that the only edges targeting
           ti in the old graph are entry and dot (both removed), and any
           dotdot edge to ti would also be removed or impossible. *)
        (* Let's check: could there be a dotdot edge to ti?
           That would mean some directory has ".." pointing to ti.
           But ti IS a directory with its own ".." pointing to pi.
           Another directory's ".." to ti would mean that directory is
           a child of ti. But ti is empty (Hempty), so no children. *)
        (* For now, we note this case doesn't arise in well-formed graphs
           with our preconditions. The proof would require additional
           machinery about link_count = 2. We use the emptiness +
           uniqueness to establish no surviving edges target ti. *)
        apply Hne1.
        assert (Hne2 := remove_three_edges_not_e2 _ _ _ _ _ Hin).
        (* e targets ti, e ≠ entry, e ≠ dot.
           e is in old edges. By UniqueNamesPerDir, no two edges from
           the same dir can have the same name targeting the same inode.
           We need to show e can't exist. *)
        (* Case: ce_dir e = pd. Then name must differ from name.
           Or ce_dir e = td. Then we showed ce_dir e ≠ td above.
           Actually we proved ce_dir e ≠ td above. So ce_dir e ≠ td.
           And e ≠ (pd, ti, name). So either ce_dir e ≠ pd or ce_name e ≠ name.
           Either way, e is an edge from some dir to ti. This is possible
           if someone else hard-linked to ti. But GC-LINK-2 prevents
           linking to directories. So no non-entry, non-dot edge targets ti.

           We need lp_is_regular from LinkPre to know this. But our
           RmdirPre doesn't encode "no one can hard-link to directories."

           The safest approach: add a precondition that the only
           non-dotdot edges targeting ti are entry and dot. *)
        (* WORKAROUND: We don't have this precondition, so we admit
           this sub-case. In a complete formalization, we would add
           rmp_only_two_links or derive it from GC-LINK-2. *)
        admit. }
      unfold inode_exists, inode_ids in Hi.
      apply in_map_iff in Hi. destruct Hi as [ir [Hir_id Hir_in]].
      apply in_map_iff. exists ir. split.
      * exact Hir_id.
      * apply remove_inode_preserves; [ exact Hir_in | ].
        rewrite <- Hir_id. exact Hce_ino_ne.
  - (* NoDupInodeIds *)
    unfold NoDupInodeIds, inode_ids, rmdir. simpl.
    apply remove_inode_NoDup. exact HnodupI.
  - (* NoDupDirIds *)
    unfold NoDupDirIds, dir_ids, rmdir. simpl.
    apply remove_dir_NoDup. exact HnodupD.
Admitted.
(* NOTE: The proof is complete except for one sub-case: showing that
   no surviving edge targets the removed inode ti. This requires the
   additional fact that directories cannot be hard-linked (GC-LINK-2),
   so the only incoming edges to ti are the entry edge and the dot edge,
   both of which are removed. A full formalization would add this as
   a precondition (rmp_only_links) or derive it from a NoHardLinkToDir
   invariant added to WellFormed. *)

(* ===================================================================== *)
(* 6. THEOREM: rmdir preserves UniqueNamesPerDir                         *)
(* ===================================================================== *)

(* Removing edges and directories can only make names more unique. *)

Theorem rmdir_preserves_UniqueNamesPerDir :
  forall g pd name ti td pi,
    WellFormed g ->
    RmdirPre g pd name ti td pi ->
    UniqueNamesPerDir (rmdir g pd name ti td pi).
Proof.
  intros g pd name ti td pi HWF Hpre.
  destruct HWF as [HTI [HLC [HUN [HND HNC]]]].
  unfold UniqueNamesPerDir.
  intros e1 e2 Hin1 Hin2 Hdir Hname.
  unfold rmdir in Hin1, Hin2. simpl in Hin1, Hin2.
  apply remove_three_edges_subset in Hin1.
  apply remove_three_edges_subset in Hin2.
  apply HUN; assumption.
Qed.

(* ===================================================================== *)
(* 7. THEOREM: rmdir preserves NoDanglingEdges                           *)
(* ===================================================================== *)

(* This requires the same argument as TypeInvariant — surviving edges
   don't target removed nodes. *)

Theorem rmdir_preserves_NoDanglingEdges :
  forall g pd name ti td pi,
    WellFormed g ->
    RmdirPre g pd name ti td pi ->
    NoDanglingEdges (rmdir g pd name ti td pi).
Proof.
  intros g pd name ti td pi HWF Hpre.
  (* Same structure as TypeInvariant — endpoints of surviving edges
     are not the removed nodes. *)
  destruct HWF as [HTI [HLC [HUN [HND HNC]]]].
  destruct Hpre as [Hdir Huser He Hdot Hddot Hisdir Htgt Htd Htdlink Hempty Hpi Htne Hine].
  unfold NoDanglingEdges.
  intros e Hin.
  assert (Hin_orig := remove_three_edges_subset _ _ _ _ _ Hin).
  destruct (HND e Hin_orig) as [Hd_orig Hi_orig].
  split.
  - (* dir_exists *) admit.  (* Same argument as TypeInvariant *)
  - (* inode_exists *) admit. (* Same argument as TypeInvariant *)
Admitted.
(* NOTE: Structurally identical to TypeInvariant proof. Same sub-case
   issue with proving no surviving edge targets the removed inode. *)

(* ===================================================================== *)
(* 8. THEOREM: rmdir preserves NoDirCycles                               *)
(* ===================================================================== *)

(* Removing nodes and edges can only break cycles, never create them. *)

Theorem rmdir_preserves_NoDirCycles :
  forall g pd name ti td pi,
    WellFormed g ->
    RmdirPre g pd name ti td pi ->
    NoDirCycles (rmdir g pd name ti td pi).
Proof.
  intros g pd name ti td pi HWF Hpre.
  destruct HWF as [HTI [HLC [HUN [HND HNC]]]].
  destruct HNC as [rank Hrank].
  exists rank.
  intros e Hin Huser_name ir Hfind Hvtype child_dir Hchild.
  unfold rmdir in Hin. simpl in Hin.
  apply remove_three_edges_subset in Hin.
  (* find_inode through remove_inode: if found, it was in old graph *)
  unfold find_inode in Hfind. unfold rmdir in Hfind. simpl in Hfind.
  unfold remove_inode in Hfind.
  (* find through filter preserves the found element *)
  assert (Hfind_orig : exists ir_old,
    find_inode g (ce_ino e) = Some ir_old /\ ir_vtype ir_old = DirectoryType).
  { unfold find_inode.
    induction (g_inodes g) as [|h t IH].
    - simpl in Hfind. discriminate.
    - simpl in Hfind.
      destruct (Nat.eqb (ir_id h) ti) eqn:Hti.
      + (* h is the removed inode — skipped by filter *)
        simpl in Hfind. apply IH. exact Hfind.
      + simpl in Hfind.
        destruct (Nat.eqb (ir_id h) (ce_ino e)) eqn:Hid.
        * inversion Hfind. subst. simpl.
          exists h. split; [ | exact Hvtype ].
          simpl. rewrite Hid. reflexivity.
        * apply IH. exact Hfind. }
  destruct Hfind_orig as [ir_old [Hfo Hvo]].
  (* dir_for_inode through remove_dir *)
  unfold dir_for_inode in Hchild. unfold rmdir in Hchild. simpl in Hchild.
  assert (Hchild_orig : dir_for_inode g (ce_ino e) = Some child_dir).
  { unfold dir_for_inode, remove_dir in Hchild.
    induction (g_dirs g) as [|h t IH].
    - simpl in Hchild. discriminate.
    - simpl in Hchild.
      destruct (Nat.eqb (dr_id h) td) eqn:Htd_eq.
      + simpl in Hchild. unfold dir_for_inode.
        simpl. destruct (Nat.eqb (dr_inode_id h) (ce_ino e)) eqn:Hmatch.
        * (* h is the removed dir but matches — ce_ino e = target_ino *)
          apply Nat.eqb_eq in Hmatch. apply Nat.eqb_eq in Htd_eq.
          (* h = mkDir td ti, so ce_ino e = ti.
             But ir_old has vtype = DirectoryType and find_inode g ti = Some ir_old.
             The edge e from old graph targets ti and has DirectoryType target.
             Since the edge is from the old graph, and td is being removed,
             child_dir must be td. But td is removed, so find through
             remove_dir should skip it. We need child_dir from the REMAINING
             dirs. If the ONLY dir with inode ti is td (which is being removed),
             then find through remove_dir gives None, contradicting Hchild.
             So there must be another dir with inode ti. This is unlikely
             given NoDupDirIds but possible.
             For safety, we route through IH. *)
          specialize (IH Hchild).
          unfold dir_for_inode in IH. simpl in IH.
          rewrite Hmatch in IH. exact IH.
        * simpl. rewrite Hmatch. apply IH. exact Hchild.
      + simpl in Hchild.
        destruct (Nat.eqb (dr_inode_id h) (ce_ino e)) eqn:Hmatch.
        * inversion Hchild. subst. unfold dir_for_inode.
          simpl. rewrite Hmatch. reflexivity.
        * unfold dir_for_inode. simpl. rewrite Hmatch.
          apply IH. exact Hchild. }
  apply (Hrank e Hin Huser_name ir_old Hfo Hvo child_dir Hchild_orig).
Qed.

(* ===================================================================== *)
(* 9. MAIN THEOREM: rmdir preserves WellFormed (modulo TypeInvariant)    *)
(* ===================================================================== *)

(* The full WellFormed preservation depends on closing the TypeInvariant
   and NoDanglingEdges sub-cases, which require the NoHardLinkToDir
   invariant. We state the theorem with Admitted for transparency. *)

Theorem rmdir_preserves_WellFormed :
  forall g pd name ti td pi,
    WellFormed g ->
    RmdirPre g pd name ti td pi ->
    WellFormed (rmdir g pd name ti td pi).
Proof.
  intros g pd name ti td pi HWF Hpre.
  unfold WellFormed. repeat split.
  - exact (rmdir_preserves_TypeInvariant g pd name ti td pi HWF Hpre).
  - admit. (* LinkCountConsistent — same counting argument as unlink *)
  - exact (rmdir_preserves_UniqueNamesPerDir g pd name ti td pi HWF Hpre).
  - exact (rmdir_preserves_NoDanglingEdges g pd name ti td pi HWF Hpre).
  - exact (rmdir_preserves_NoDirCycles g pd name ti td pi HWF Hpre).
Admitted.
(* NOTE: The admits are for:
   1. TypeInvariant/NoDanglingEdges: proving no surviving edge targets
      the removed inode (requires NoHardLinkToDir invariant)
   2. LinkCountConsistent: counting argument that removing 2 non-dotdot
      edges (entry + dot) and the inode itself preserves the invariant
      for all remaining inodes.
   These are mechanically involved but conceptually straightforward.
   The NoDirCycles and UniqueNamesPerDir proofs are complete. *)
