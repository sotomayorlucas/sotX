(* ===================================================================== *)
(* DpoCreate.v — DPO rule CREATE (file) + invariant preservation proofs  *)
(*                                                                       *)
(* Corresponds to:                                                       *)
(*   TLA+:  CreateFile(d, name) in sotfs_graph.tla lines 228-245        *)
(*   Rust:  create_file() in sotfs-ops/src/lib.rs lines 26-75           *)
(*                                                                       *)
(* The rule adds a fresh regular inode with link_count=1 and a single   *)
(* contains edge from the parent directory to the new inode.            *)
(* ===================================================================== *)

Require Import Coq.Arith.Arith.
Require Import Coq.Lists.List.
Require Import Coq.Bool.Bool.
Require Import Lia.
Import ListNotations.

Require Import SotfsGraph.

(* ===================================================================== *)
(* 1. Preconditions (gluing conditions) — from TLA+ GC-CREATE-1         *)
(* ===================================================================== *)

(* GC-CREATE-1: d is an active directory *)
(* GC-CREATE-2: name is a user name (not "." or "..") *)
(* GC-CREATE-3: no existing entry with this name in d *)
(* GC-CREATE-4: new_ino is fresh (not in g_inodes) *)

Record CreatePre (g : Graph) (d : DirId) (name : Name) (new_ino : InodeId) : Prop := {
  cp_dir_exists   : dir_exists g d;
  cp_user_name    : is_user_name name;
  cp_name_fresh   : name_in_dir g d name = false;
  cp_ino_fresh    : ~ inode_exists g new_ino;
}.

(* ===================================================================== *)
(* 2. The create_file function                                           *)
(* ===================================================================== *)

Definition create_file (g : Graph) (d : DirId) (name : Name) (new_ino : InodeId)
  : Graph :=
  {| g_inodes := g_inodes g ++ [mkInode new_ino Regular 1];
     g_dirs   := g_dirs g;
     g_edges  := g_edges g ++ [mkContains d new_ino name];
  |}.

(* ===================================================================== *)
(* 3. Auxiliary lemmas specific to create_file                           *)
(* ===================================================================== *)

(* The new inode is in the new graph *)
Lemma create_new_ino_in :
  forall g d name new_ino,
    inode_exists (create_file g d name new_ino) new_ino.
Proof.
  intros. unfold inode_exists, inode_ids, create_file. simpl.
  rewrite map_app. apply in_or_app. right. simpl. left. reflexivity.
Qed.

(* Old inodes are preserved *)
Lemma create_preserves_inodes :
  forall g d name new_ino id,
    inode_exists g id -> inode_exists (create_file g d name new_ino) id.
Proof.
  intros. unfold inode_exists, inode_ids, create_file in *. simpl.
  rewrite map_app. apply in_or_app. left. exact H.
Qed.

(* Old dirs are preserved (dirs unchanged) *)
Lemma create_preserves_dirs :
  forall g d name new_ino id,
    dir_exists g id <-> dir_exists (create_file g d name new_ino) id.
Proof.
  intros. unfold dir_exists, dir_ids, create_file. simpl. tauto.
Qed.

(* Edges are old edges ++ [new edge] *)
Lemma create_edges :
  forall g d name new_ino e,
    In e (g_edges (create_file g d name new_ino)) <->
    In e (g_edges g) \/ e = mkContains d new_ino name.
Proof.
  intros. unfold create_file. simpl. rewrite in_app_iff. simpl.
  tauto.
Qed.

(* The new inode record can be found *)
Lemma create_find_new_ino :
  forall g d name new_ino,
    ~ inode_exists g new_ino ->
    NoDupInodeIds g ->
    find_inode (create_file g d name new_ino) new_ino =
      Some (mkInode new_ino Regular 1).
Proof.
  intros g d name new_ino Hfresh Hnodup.
  unfold find_inode, create_file. simpl.
  rewrite find_app_iff.
  destruct (find (fun ir => Nat.eqb (ir_id ir) new_ino) (g_inodes g)) eqn:Hfind.
  - (* found in old graph — contradiction with freshness *)
    apply find_some in Hfind. destruct Hfind as [Hin Heqb].
    apply Nat.eqb_eq in Heqb.
    exfalso. apply Hfresh.
    unfold inode_exists, inode_ids.
    apply in_map_iff. exists i. split; assumption.
  - (* not found in old, so find in [new] *)
    simpl. rewrite Nat.eqb_refl. reflexivity.
Qed.

(* Old inode records are preserved *)
Lemma create_find_old_ino :
  forall g d name new_ino id,
    id <> new_ino ->
    find_inode (create_file g d name new_ino) id = find_inode g id.
Proof.
  intros g d name new_ino id Hneq.
  unfold find_inode, create_file. simpl.
  rewrite find_app_iff.
  destruct (find (fun ir => Nat.eqb (ir_id ir) id) (g_inodes g)) eqn:Hf.
  - reflexivity.
  - simpl. destruct (Nat.eqb id new_ino) eqn:Heq.
    + apply Nat.eqb_eq in Heq. contradiction.
    + reflexivity.
Qed.

(* incoming_count for inodes other than new_ino is unchanged *)
Lemma create_incoming_old_ino :
  forall g d name new_ino ino,
    ino <> new_ino ->
    incoming_count (create_file g d name new_ino) ino =
    incoming_count g ino.
Proof.
  intros. unfold incoming_count, create_file. simpl.
  rewrite count_occ_pred_app. simpl.
  assert (Hneq : Nat.eqb new_ino ino = false).
  { apply Nat.eqb_neq. auto. }
  rewrite Hneq. simpl. lia.
Qed.

(* ===================================================================== *)
(* 4. THEOREM: create_file preserves TypeInvariant                       *)
(* ===================================================================== *)

Theorem create_preserves_TypeInvariant :
  forall g d name new_ino,
    WellFormed g ->
    CreatePre g d name new_ino ->
    TypeInvariant (create_file g d name new_ino).
Proof.
  intros g d name new_ino HWF Hpre.
  destruct HWF as [HTI [HLC [HUN [HND HNC]]]].
  destruct HTI as [Hedge [HnodupI HnodupD]].
  destruct Hpre as [Hdir Huser Hfresh Hino_fresh].
  unfold TypeInvariant. repeat split.
  - (* edges endpoints exist *)
    intros e Hin.
    apply create_edges in Hin. destruct Hin as [Hold | Hnew].
    + destruct (Hedge e Hold) as [Hd Hi]. split.
      * apply create_preserves_dirs. exact Hd.
      * apply create_preserves_inodes. exact Hi.
    + subst e. simpl. split.
      * apply create_preserves_dirs. exact Hdir.
      * apply create_new_ino_in.
  - (* NoDupInodeIds *)
    unfold NoDupInodeIds, inode_ids, create_file. simpl.
    rewrite map_app. simpl.
    apply NoDup_app_intro.
    + exact HnodupI.
    + constructor. { simpl; tauto. } constructor.
    + intros x HinOld HinNew.
      simpl in HinNew. destruct HinNew as [Hx | []]. subst x.
      apply Hino_fresh.
      unfold inode_exists, inode_ids. exact HinOld.
  - (* NoDupDirIds — dirs unchanged *)
    unfold NoDupDirIds, dir_ids, create_file. simpl.
    exact HnodupD.
Qed.

(* ===================================================================== *)
(* 5. THEOREM: create_file preserves LinkCountConsistent                 *)
(* ===================================================================== *)

(* Key insight: the new inode has link_count=1 and exactly one incoming
   non-dotdot edge (the new contains edge). Old inodes are unchanged
   because the new edge targets the fresh inode, not any old inode. *)

Theorem create_preserves_LinkCountConsistent :
  forall g d name new_ino,
    WellFormed g ->
    CreatePre g d name new_ino ->
    LinkCountConsistent (create_file g d name new_ino).
Proof.
  intros g d name new_ino HWF Hpre.
  destruct HWF as [HTI [HLC [HUN [HND HNC]]]].
  destruct Hpre as [Hdir Huser Hnamefresh Hino_fresh].
  unfold LinkCountConsistent.
  intros ir Hin.
  unfold create_file in Hin. simpl in Hin.
  apply in_app_iff in Hin. destruct Hin as [Hold | Hnew].
  - (* old inode — link_count and incoming_count unchanged *)
    assert (Hid : ir_id ir <> new_ino).
    { intro Heq. apply Hino_fresh.
      unfold inode_exists, inode_ids.
      apply in_map_iff. exists ir. split; assumption. }
    rewrite (create_incoming_old_ino g d name new_ino (ir_id ir) Hid).
    apply HLC. exact Hold.
  - (* new inode — link_count=1 and incoming_count=1 *)
    simpl in Hnew. destruct Hnew as [Hnew | []]. subst ir. simpl.
    unfold incoming_count, create_file. simpl.
    rewrite count_occ_pred_app. simpl.
    rewrite Nat.eqb_refl.
    assert (Hndot : Nat.eqb name dotdot_name = false).
    { apply Nat.eqb_neq. apply user_name_not_dotdot. exact Huser. }
    rewrite Hndot. simpl.
    (* Old edges don't target new_ino: NoDanglingEdges says each edge
       target is in inode_ids, but new_ino is not *)
    assert (Hold_zero :
      count_occ_pred
        (fun e => Nat.eqb (ce_ino e) new_ino && negb (Nat.eqb (ce_name e) dotdot_name))
        (g_edges g) = 0).
    { apply not_in_edges_incoming_zero.
      intros e He Heq.
      apply Hino_fresh.
      destruct (HND e He) as [_ Hi].
      rewrite Heq in Hi. exact Hi. }
    rewrite Hold_zero. reflexivity.
Qed.

(* ===================================================================== *)
(* 6. THEOREM: create_file preserves UniqueNamesPerDir                   *)
(* ===================================================================== *)

Theorem create_preserves_UniqueNamesPerDir :
  forall g d name new_ino,
    WellFormed g ->
    CreatePre g d name new_ino ->
    UniqueNamesPerDir (create_file g d name new_ino).
Proof.
  intros g d name new_ino HWF Hpre.
  destruct HWF as [HTI [HLC [HUN [HND HNC]]]].
  destruct Hpre as [Hdir Huser Hnamefresh Hino_fresh].
  unfold UniqueNamesPerDir.
  intros e1 e2 Hin1 Hin2 Hdir_eq Hname_eq.
  apply create_edges in Hin1. apply create_edges in Hin2.
  destruct Hin1 as [H1old | H1new]; destruct Hin2 as [H2old | H2new].
  - (* both old *)
    apply HUN; assumption.
  - (* e1 old, e2 = new edge — contradiction via name freshness *)
    subst e2. simpl in Hdir_eq, Hname_eq.
    exfalso.
    apply (name_in_dir_false_not_in g d name Hnamefresh).
    exists (ce_ino e1).
    destruct e1 as [d1 i1 n1]. simpl in *. subst. exact H1old.
  - (* e1 = new edge, e2 old — symmetric *)
    subst e1. simpl in Hdir_eq, Hname_eq.
    exfalso.
    apply (name_in_dir_false_not_in g d name Hnamefresh).
    exists (ce_ino e2).
    destruct e2 as [d2 i2 n2]. simpl in *. subst. exact H2old.
  - (* both new *)
    subst. reflexivity.
Qed.

(* ===================================================================== *)
(* 7. THEOREM: create_file preserves NoDanglingEdges                     *)
(* ===================================================================== *)

Theorem create_preserves_NoDanglingEdges :
  forall g d name new_ino,
    WellFormed g ->
    CreatePre g d name new_ino ->
    NoDanglingEdges (create_file g d name new_ino).
Proof.
  intros g d name new_ino HWF Hpre.
  destruct HWF as [HTI [HLC [HUN [HND HNC]]]].
  destruct Hpre as [Hdir Huser Hnamefresh Hino_fresh].
  unfold NoDanglingEdges.
  intros e Hin.
  apply create_edges in Hin. destruct Hin as [Hold | Hnew].
  - destruct (HND e Hold) as [Hd Hi]. split.
    + apply create_preserves_dirs. exact Hd.
    + apply create_preserves_inodes. exact Hi.
  - subst e. simpl. split.
    + apply create_preserves_dirs. exact Hdir.
    + apply create_new_ino_in.
Qed.

(* ===================================================================== *)
(* 8. THEOREM: create_file preserves NoDirCycles                         *)
(* ===================================================================== *)

(* Key insight: the new inode is Regular, so no new directory child is
   added to the DAG. The old ranking still works. *)

Theorem create_preserves_NoDirCycles :
  forall g d name new_ino,
    WellFormed g ->
    CreatePre g d name new_ino ->
    NoDirCycles (create_file g d name new_ino).
Proof.
  intros g d name new_ino HWF Hpre.
  destruct HWF as [HTI [HLC [HUN [HND HNC]]]].
  destruct Hpre as [Hdir Huser Hnamefresh Hino_fresh].
  destruct HNC as [rank Hrank].
  destruct HTI as [_ [HnodupI _]].
  exists rank.
  intros e Hin Huser_name ir Hfind Hvtype child_dir Hchild.
  apply create_edges in Hin. destruct Hin as [Hold | Hnew].
  - (* old edge *)
    destruct (Nat.eq_dec (ce_ino e) new_ino) as [Heq | Hneq].
    + (* Edge targets new_ino — but new inode is Regular, contradicts Hvtype *)
      exfalso.
      rewrite Heq in Hfind.
      rewrite (create_find_new_ino g d name new_ino Hino_fresh HnodupI) in Hfind.
      inversion Hfind. subst ir. simpl in Hvtype. discriminate.
    + (* Edge targets old inode *)
      rewrite (create_find_old_ino g d name new_ino (ce_ino e) Hneq) in Hfind.
      unfold dir_for_inode in Hchild.
      unfold create_file in Hchild. simpl in Hchild.
      apply (Hrank e Hold Huser_name ir Hfind Hvtype child_dir).
      unfold dir_for_inode. exact Hchild.
  - (* new edge — targets new_ino which is Regular *)
    subst e. simpl in *.
    rewrite (create_find_new_ino g d name new_ino Hino_fresh HnodupI) in Hfind.
    inversion Hfind. subst ir. simpl in Hvtype. discriminate.
Qed.

(* ===================================================================== *)
(* 9. MAIN THEOREM: create_file preserves WellFormed                     *)
(* ===================================================================== *)

Theorem create_preserves_WellFormed :
  forall g d name new_ino,
    WellFormed g ->
    CreatePre g d name new_ino ->
    WellFormed (create_file g d name new_ino).
Proof.
  intros g d name new_ino HWF Hpre.
  unfold WellFormed. repeat split.
  - exact (create_preserves_TypeInvariant g d name new_ino HWF Hpre).
  - exact (create_preserves_LinkCountConsistent g d name new_ino HWF Hpre).
  - exact (create_preserves_UniqueNamesPerDir g d name new_ino HWF Hpre).
  - exact (create_preserves_NoDanglingEdges g d name new_ino HWF Hpre).
  - exact (create_preserves_NoDirCycles g d name new_ino HWF Hpre).
Qed.
