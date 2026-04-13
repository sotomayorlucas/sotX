(* ===================================================================== *)
(* DpoUnlink.v — DPO rule UNLINK + invariant preservation proofs         *)
(*                                                                       *)
(* Corresponds to:                                                       *)
(*   TLA+:  Unlink(d, name) in sotfs_graph.tla lines 345-381            *)
(*   Rust:  unlink() in sotfs-ops/src/lib.rs lines 310-378              *)
(*                                                                       *)
(* The rule removes a contains edge from dir d with label name.          *)
(* It decrements link_count; if link_count reaches 0 the inode is        *)
(* garbage-collected (removed from the graph).                           *)
(*                                                                       *)
(* We prove the non-GC case (link_count >= 2 before removal, so the     *)
(* inode remains with link_count - 1). This is the common case for       *)
(* files with multiple hard links or a single link that is NOT the last. *)
(* The GC case (inode removal) is analogous but involves node deletion.  *)
(* ===================================================================== *)

Require Import Coq.Arith.Arith.
Require Import Coq.Lists.List.
Require Import Coq.Bool.Bool.
Require Import Lia.
Import ListNotations.

Require Import SotfsGraph.

(* ===================================================================== *)
(* 1. Preconditions (gluing conditions)                                  *)
(* ===================================================================== *)

Record UnlinkPre (g : Graph) (d : DirId) (name : Name) (target_ino : InodeId)
  : Prop := {
  up_dir_exists   : dir_exists g d;
  up_user_name    : is_user_name name;
  up_edge_exists  : In (mkContains d target_ino name) (g_edges g);
  up_is_regular   : forall ir, find_inode g target_ino = Some ir ->
                       ir_vtype ir = Regular;
  up_target_exists : inode_exists g target_ino;
}.

(* Additional precondition: target has link_count >= 2 (non-GC case) *)
Definition UnlinkKeepPre (g : Graph) (target_ino : InodeId) : Prop :=
  forall ir, find_inode g target_ino = Some ir ->
    ir_link_count ir >= 2.

(* ===================================================================== *)
(* 2. Helper: replace link_count of one inode                            *)
(* ===================================================================== *)

Definition decrement_link (inodes : list InodeRec) (ino : InodeId) : list InodeRec :=
  map (fun ir =>
    if Nat.eqb (ir_id ir) ino
    then mkInode (ir_id ir) (ir_vtype ir) (pred (ir_link_count ir))
    else ir
  ) inodes.

Lemma decrement_link_preserves_ids :
  forall inodes ino,
    map ir_id (decrement_link inodes ino) = map ir_id inodes.
Proof.
  intros. unfold decrement_link.
  rewrite map_map. apply map_ext.
  intro a. simpl. destruct (Nat.eqb (ir_id a) ino); reflexivity.
Qed.

Lemma decrement_link_In :
  forall inodes ino ir,
    In ir inodes ->
    ir_id ir <> ino ->
    In ir (decrement_link inodes ino).
Proof.
  intros inodes ino ir Hin Hneq.
  unfold decrement_link. apply in_map_iff.
  exists ir. split.
  - destruct (Nat.eqb (ir_id ir) ino) eqn:Heq.
    + apply Nat.eqb_eq in Heq. contradiction.
    + reflexivity.
  - exact Hin.
Qed.

(* ===================================================================== *)
(* 3. The unlink_keep function (non-GC case)                             *)
(* ===================================================================== *)

Definition unlink_keep (g : Graph) (d : DirId) (target_ino : InodeId) (name : Name)
  : Graph :=
  {| g_inodes := decrement_link (g_inodes g) target_ino;
     g_dirs   := g_dirs g;
     g_edges  := remove_edge (mkContains d target_ino name) (g_edges g);
  |}.

(* ===================================================================== *)
(* 4. THEOREM: unlink_keep preserves TypeInvariant                       *)
(* ===================================================================== *)

Theorem unlink_keep_preserves_TypeInvariant :
  forall g d name target_ino,
    WellFormed g ->
    UnlinkPre g d name target_ino ->
    TypeInvariant (unlink_keep g d target_ino name).
Proof.
  intros g d name target_ino HWF Hpre.
  destruct HWF as [HTI [HLC [HUN [HND HNC]]]].
  destruct HTI as [Hedge [HnodupI HnodupD]].
  destruct Hpre as [Hdir Huser Hedge Hreg Htgt].
  unfold TypeInvariant. repeat split.
  - (* endpoints exist *)
    intros e Hin.
    unfold unlink_keep in Hin. simpl in Hin.
    apply remove_edge_subset in Hin.
    destruct (HND e Hin) as [Hd Hi]. split.
    + unfold dir_exists, dir_ids, unlink_keep. simpl. exact Hd.
    + unfold inode_exists, inode_ids, unlink_keep. simpl.
      rewrite decrement_link_preserves_ids. exact Hi.
  - (* NoDupInodeIds *)
    unfold NoDupInodeIds, inode_ids, unlink_keep. simpl.
    rewrite decrement_link_preserves_ids. exact HnodupI.
  - (* NoDupDirIds — dirs unchanged *)
    unfold NoDupDirIds, dir_ids, unlink_keep. simpl. exact HnodupD.
Qed.

(* ===================================================================== *)
(* 5. THEOREM: unlink_keep preserves UniqueNamesPerDir                   *)
(* ===================================================================== *)

(* Removing an edge can only make names more unique, never less. *)

Theorem unlink_keep_preserves_UniqueNamesPerDir :
  forall g d name target_ino,
    WellFormed g ->
    UnlinkPre g d name target_ino ->
    UniqueNamesPerDir (unlink_keep g d target_ino name).
Proof.
  intros g d name target_ino HWF Hpre.
  destruct HWF as [HTI [HLC [HUN [HND HNC]]]].
  unfold UniqueNamesPerDir.
  intros e1 e2 Hin1 Hin2 Hdir Hname.
  unfold unlink_keep in Hin1, Hin2. simpl in Hin1, Hin2.
  apply remove_edge_subset in Hin1.
  apply remove_edge_subset in Hin2.
  apply HUN; assumption.
Qed.

(* ===================================================================== *)
(* 6. THEOREM: unlink_keep preserves NoDanglingEdges                     *)
(* ===================================================================== *)

Theorem unlink_keep_preserves_NoDanglingEdges :
  forall g d name target_ino,
    WellFormed g ->
    UnlinkPre g d name target_ino ->
    NoDanglingEdges (unlink_keep g d target_ino name).
Proof.
  intros g d name target_ino HWF Hpre.
  destruct HWF as [HTI [HLC [HUN [HND HNC]]]].
  unfold NoDanglingEdges.
  intros e Hin.
  unfold unlink_keep in Hin. simpl in Hin.
  apply remove_edge_subset in Hin.
  destruct (HND e Hin) as [Hd Hi]. split.
  - unfold dir_exists, dir_ids, unlink_keep. simpl. exact Hd.
  - unfold inode_exists, inode_ids, unlink_keep. simpl.
    rewrite decrement_link_preserves_ids. exact Hi.
Qed.

(* ===================================================================== *)
(* 7. THEOREM: unlink_keep preserves LinkCountConsistent                 *)
(* ===================================================================== *)

(* Key insight: removing edge (d, target_ino, name) decreases            *)
(* incoming_count(target_ino) by exactly 1 (because name is a user name, *)
(* not "..", and UniqueNamesPerDir ensures it appears exactly once).      *)
(* decrement_link decreases link_count by 1. For all other inodes,       *)
(* both incoming_count and link_count are unchanged.                     *)

(* Incoming count for non-target inodes is unchanged *)
Lemma unlink_incoming_other :
  forall g d target_ino name ino,
    ino <> target_ino ->
    incoming_count (unlink_keep g d target_ino name) ino =
    incoming_count g ino.
Proof.
  intros g d target_ino name ino Hneq.
  unfold incoming_count, unlink_keep. simpl.
  induction (g_edges g) as [|h t IH].
  - reflexivity.
  - simpl. destruct (ce_eqb h (mkContains d target_ino name)) eqn:Heq_edge.
    + (* h = removed edge — it targets target_ino, not ino *)
      apply ce_eqb_eq in Heq_edge. subst h. simpl.
      assert (Hneqb : Nat.eqb target_ino ino = false).
      { apply Nat.eqb_neq. exact Hneq. }
      rewrite Hneqb. simpl. reflexivity.
    + (* h kept *)
      simpl.
      destruct (Nat.eqb (ce_ino h) ino && negb (Nat.eqb (ce_name h) dotdot_name))
        eqn:Hpred.
      * simpl. f_equal. exact IH.
      * exact IH.
Qed.

(* Incoming count for target_ino decreases by 1 *)
(* This requires that the edge appears exactly once (UniqueNamesPerDir). *)
(* We prove a slightly weaker but sufficient version using Admitted for   *)
(* the list-level uniqueness reasoning.                                  *)

Lemma unlink_incoming_target :
  forall g d target_ino name,
    WellFormed g ->
    In (mkContains d target_ino name) (g_edges g) ->
    is_user_name name ->
    incoming_count (unlink_keep g d target_ino name) target_ino =
    pred (incoming_count g target_ino).
Proof.
  intros g d target_ino name HWF Hin Huser.
  unfold incoming_count, unlink_keep. simpl.
  apply count_remove_matching_pred.
  - exact Hin.
  - (* The removed edge satisfies the incoming_count predicate *)
    simpl. rewrite Nat.eqb_refl.
    assert (Hndot : Nat.eqb name dotdot_name = false).
    { apply Nat.eqb_neq. apply user_name_not_dotdot. exact Huser. }
    rewrite Hndot. reflexivity.
Qed.

Theorem unlink_keep_preserves_LinkCountConsistent :
  forall g d name target_ino,
    WellFormed g ->
    UnlinkPre g d name target_ino ->
    UnlinkKeepPre g target_ino ->
    LinkCountConsistent (unlink_keep g d target_ino name).
Proof.
  intros g d name target_ino HWF Hpre Hkeep.
  destruct HWF as [HTI [HLC [HUN [HND HNC]]]].
  destruct HTI as [Hedge [HnodupI HnodupD]].
  destruct Hpre as [Hdir Huser Hedge_in Hreg Htgt_exists].
  unfold LinkCountConsistent.
  intros ir Hin.
  unfold unlink_keep in Hin. simpl in Hin.
  unfold decrement_link in Hin. apply in_map_iff in Hin.
  destruct Hin as [ir_old [Heq Hin_old]].
  destruct (Nat.eq_dec (ir_id ir_old) target_ino) as [Htgt | Hntgt].
  - (* ir_old is the target inode — link_count decremented *)
    assert (Heqb : Nat.eqb (ir_id ir_old) target_ino = true).
    { apply Nat.eqb_eq. exact Htgt. }
    rewrite Heqb in Heq. subst ir. simpl.
    rewrite Htgt.
    rewrite (unlink_incoming_target g d target_ino name).
    + (* pred link_count = pred incoming_count *)
      f_equal. apply HLC. exact Hin_old.
    + unfold WellFormed. repeat split; assumption.
    + exact Hedge_in.
    + exact Huser.
  - (* ir_old is not the target — unchanged *)
    assert (Heqb : Nat.eqb (ir_id ir_old) target_ino = false).
    { apply Nat.eqb_neq. exact Hntgt. }
    rewrite Heqb in Heq. subst ir.
    rewrite (unlink_incoming_other g d target_ino name (ir_id ir_old) Hntgt).
    apply HLC. exact Hin_old.
Qed.

(* ===================================================================== *)
(* 8. THEOREM: unlink_keep preserves NoDirCycles                         *)
(* ===================================================================== *)

(* Removing an edge can only break cycles, never create them.
   The old ranking still works on the subset of edges. *)

Theorem unlink_keep_preserves_NoDirCycles :
  forall g d name target_ino,
    WellFormed g ->
    UnlinkPre g d name target_ino ->
    NoDirCycles (unlink_keep g d target_ino name).
Proof.
  intros g d name target_ino HWF Hpre.
  destruct HWF as [HTI [HLC [HUN [HND HNC]]]].
  destruct HNC as [rank Hrank].
  destruct Hpre as [Hdir Huser Hedge_in Hreg Htgt_exists].
  exists rank.
  intros e Hin Huser_name ir Hfind Hvtype child_dir Hchild.
  (* e is in the reduced edge list — lift to original *)
  unfold unlink_keep in Hin. simpl in Hin.
  apply remove_edge_subset in Hin.
  (* find_inode through decrement_link preserves vtype *)
  unfold find_inode in Hfind. unfold unlink_keep in Hfind. simpl in Hfind.
  unfold decrement_link in Hfind.
  (* Use the helper lemma to get the original inode record *)
  apply decrement_link_preserves_vtype in Hfind; [ | exact Hvtype ].
  destruct Hfind as [ir_old [Hfind_old Hvtype_old]].
  (* dir_for_inode unchanged since dirs unchanged *)
  unfold dir_for_inode in Hchild. unfold unlink_keep in Hchild. simpl in Hchild.
  apply (Hrank e Hin Huser_name ir_old).
  - unfold find_inode. exact Hfind_old.
  - exact Hvtype_old.
  - unfold dir_for_inode. exact Hchild.
Qed.

(* ===================================================================== *)
(* 9. MAIN THEOREM: unlink_keep preserves WellFormed                     *)
(* ===================================================================== *)

Theorem unlink_keep_preserves_WellFormed :
  forall g d name target_ino,
    WellFormed g ->
    UnlinkPre g d name target_ino ->
    UnlinkKeepPre g target_ino ->
    WellFormed (unlink_keep g d target_ino name).
Proof.
  intros g d name target_ino HWF Hpre Hkeep.
  unfold WellFormed. repeat split.
  - exact (unlink_keep_preserves_TypeInvariant g d name target_ino HWF Hpre).
  - exact (unlink_keep_preserves_LinkCountConsistent g d name target_ino HWF Hpre Hkeep).
  - exact (unlink_keep_preserves_UniqueNamesPerDir g d name target_ino HWF Hpre).
  - exact (unlink_keep_preserves_NoDanglingEdges g d name target_ino HWF Hpre).
  - exact (unlink_keep_preserves_NoDirCycles g d name target_ino HWF Hpre).
Qed.
