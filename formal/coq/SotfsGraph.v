(* ===================================================================== *)
(* SotfsGraph.v — Core definitions for the sotFS type graph              *)
(*                                                                       *)
(* Formalizes the metadata graph from sotfs_graph.tla and                *)
(* sotfs-graph/src/{types,graph}.rs as Coq records and propositions.     *)
(*                                                                       *)
(* Node types: Inode, Directory (only the metadata-relevant subset).     *)
(* Edge type:  Contains (Dir -> Inode, labeled with Name).               *)
(* We omit Block/PointsTo/Capability for this formalization — they are   *)
(* orthogonal to the 3 rules under proof (create, unlink, rename).       *)
(* ===================================================================== *)

Require Import Coq.Arith.Arith.
Require Import Coq.Lists.List.
Require Import Coq.Bool.Bool.
Require Import Lia.
Import ListNotations.

(* ===================================================================== *)
(* 1. Identifiers and names — all nat for decidable equality             *)
(* ===================================================================== *)

Definition InodeId := nat.
Definition DirId := nat.
Definition Name := nat.  (* Names as nat — sufficient for structural proofs *)

(* ===================================================================== *)
(* 2. Inode type tag                                                     *)
(* ===================================================================== *)

Inductive VnodeType : Type :=
  | Regular
  | DirectoryType.

Definition vtype_eqb (a b : VnodeType) : bool :=
  match a, b with
  | Regular, Regular => true
  | DirectoryType, DirectoryType => true
  | _, _ => false
  end.

Lemma vtype_eqb_refl : forall v, vtype_eqb v v = true.
Proof. destruct v; reflexivity. Qed.

Lemma vtype_eqb_eq : forall a b, vtype_eqb a b = true <-> a = b.
Proof.
  destruct a; destruct b; simpl; split; intro H; try reflexivity;
  try discriminate.
Qed.

(* ===================================================================== *)
(* 3. Contains edge: (Dir, Inode, Name) triple                           *)
(* Mirrors TLA+'s containsEdges = set of <<dir, inode, name>>           *)
(* ===================================================================== *)

Record ContainsEdge : Type := mkContains {
  ce_dir  : DirId;
  ce_ino  : InodeId;
  ce_name : Name;
}.

Definition ce_eqb (e1 e2 : ContainsEdge) : bool :=
  Nat.eqb (ce_dir e1) (ce_dir e2) &&
  Nat.eqb (ce_ino e1) (ce_ino e2) &&
  Nat.eqb (ce_name e1) (ce_name e2).

Lemma ce_eqb_eq : forall e1 e2, ce_eqb e1 e2 = true <-> e1 = e2.
Proof.
  intros [d1 i1 n1] [d2 i2 n2]. unfold ce_eqb. simpl.
  rewrite Bool.andb_true_iff.
  rewrite Bool.andb_true_iff.
  repeat rewrite Nat.eqb_eq.
  split.
  - intros [[Hd Hi] Hn]. subst. reflexivity.
  - intro H. inversion H. auto.
Qed.

Lemma ce_eqb_refl : forall e, ce_eqb e e = true.
Proof.
  intros [d i n]. unfold ce_eqb. simpl.
  repeat rewrite Nat.eqb_refl. reflexivity.
Qed.

Definition ce_eq_dec : forall (e1 e2 : ContainsEdge), {e1 = e2} + {e1 <> e2}.
Proof.
  intros [d1 i1 n1] [d2 i2 n2].
  destruct (Nat.eq_dec d1 d2); destruct (Nat.eq_dec i1 i2);
  destruct (Nat.eq_dec n1 n2); subst;
  try (left; reflexivity);
  right; intro H; inversion H; contradiction.
Defined.

(* ===================================================================== *)
(* 4. Inode record                                                       *)
(* ===================================================================== *)

Record InodeRec : Type := mkInode {
  ir_id         : InodeId;
  ir_vtype      : VnodeType;
  ir_link_count : nat;
}.

(* ===================================================================== *)
(* 5. Directory record (Dir node paired with its inode)                  *)
(* Mirrors TLA+'s dirInode function and Rust's Directory { id, inode_id }*)
(* ===================================================================== *)

Record DirRec : Type := mkDir {
  dr_id       : DirId;
  dr_inode_id : InodeId;
}.

(* ===================================================================== *)
(* 6. Sentinel names for "." and ".."                                    *)
(* We reserve 0 = "." and 1 = ".." ; all user names are >= 2.           *)
(* ===================================================================== *)

Definition dot_name   : Name := 0.
Definition dotdot_name : Name := 1.

Definition is_user_name (n : Name) : Prop := n >= 2.
Definition is_user_name_b (n : Name) : bool := 2 <=? n.

Lemma is_user_name_b_spec : forall n, is_user_name_b n = true <-> is_user_name n.
Proof.
  intro n. unfold is_user_name_b, is_user_name.
  rewrite Nat.leb_le. lia.
Qed.

Lemma user_name_not_dotdot : forall n, is_user_name n -> n <> dotdot_name.
Proof. unfold is_user_name, dotdot_name. lia. Qed.

Lemma user_name_not_dot : forall n, is_user_name n -> n <> dot_name.
Proof. unfold is_user_name, dot_name. lia. Qed.

(* ===================================================================== *)
(* 7. The Graph record                                                   *)
(*                                                                       *)
(* Corresponds to TLA+ variables: inodes, dirs, containsEdges, etc.     *)
(* We use lists (representing finite sets) with no-duplicates invariant. *)
(* ===================================================================== *)

Record Graph : Type := mkGraph {
  g_inodes : list InodeRec;
  g_dirs   : list DirRec;
  g_edges  : list ContainsEdge;
}.

(* ===================================================================== *)
(* 8. Membership / lookup helpers                                        *)
(* ===================================================================== *)

Definition inode_ids (g : Graph) : list InodeId :=
  map ir_id (g_inodes g).

Definition dir_ids (g : Graph) : list DirId :=
  map dr_id (g_dirs g).

Definition find_inode (g : Graph) (id : InodeId) : option InodeRec :=
  find (fun ir => Nat.eqb (ir_id ir) id) (g_inodes g).

Definition find_dir (g : Graph) (id : DirId) : option DirRec :=
  find (fun dr => Nat.eqb (dr_id dr) id) (g_dirs g).

Definition dir_for_inode (g : Graph) (ino : InodeId) : option DirId :=
  match find (fun dr => Nat.eqb (dr_inode_id dr) ino) (g_dirs g) with
  | Some dr => Some (dr_id dr)
  | None => None
  end.

Definition inode_exists (g : Graph) (id : InodeId) : Prop :=
  In id (inode_ids g).

Definition dir_exists (g : Graph) (id : DirId) : Prop :=
  In id (dir_ids g).

(* ===================================================================== *)
(* 9. List-level set operations                                          *)
(* ===================================================================== *)

(* Count elements satisfying predicate *)
Fixpoint count_occ_pred {A : Type} (f : A -> bool) (l : list A) : nat :=
  match l with
  | [] => 0
  | x :: xs => (if f x then 1 else 0) + count_occ_pred f xs
  end.

(* Remove first element equal to e *)
Fixpoint remove_edge (e : ContainsEdge) (l : list ContainsEdge) : list ContainsEdge :=
  match l with
  | [] => []
  | x :: xs =>
    if ce_eqb x e then xs
    else x :: remove_edge e xs
  end.

(* All edges from a given directory *)
Definition edges_from_dir (g : Graph) (d : DirId) : list ContainsEdge :=
  filter (fun e => Nat.eqb (ce_dir e) d) (g_edges g).

(* Check if name exists in directory *)
Definition name_in_dir (g : Graph) (d : DirId) (n : Name) : bool :=
  existsb (fun e => Nat.eqb (ce_dir e) d && Nat.eqb (ce_name e) n) (g_edges g).

(* Find the inode targeted by a name in a directory *)
Definition resolve_name (g : Graph) (d : DirId) (n : Name) : option InodeId :=
  match find (fun e => Nat.eqb (ce_dir e) d && Nat.eqb (ce_name e) n) (g_edges g) with
  | Some e => Some (ce_ino e)
  | None => None
  end.

(* Count incoming contains edges for an inode, excluding ".." *)
Definition incoming_count (g : Graph) (ino : InodeId) : nat :=
  count_occ_pred
    (fun e => Nat.eqb (ce_ino e) ino && negb (Nat.eqb (ce_name e) dotdot_name))
    (g_edges g).

(* ===================================================================== *)
(* 10. NoDupIds — no duplicate IDs in node lists                         *)
(* ===================================================================== *)

Definition NoDupInodeIds (g : Graph) : Prop :=
  NoDup (inode_ids g).

Definition NoDupDirIds (g : Graph) : Prop :=
  NoDup (dir_ids g).

(* ===================================================================== *)
(* 11. THE FIVE INVARIANTS (from sotfs_graph.tla)                        *)
(* ===================================================================== *)

(* --- 5.1 TypeInvariant ---                                             *)
(* Every inode has a valid type, every edge's endpoints are alive.       *)
(* We encode the "endpoints alive" part here; type validity is by        *)
(* construction (VnodeType is a closed inductive).                       *)

Definition TypeInvariant (g : Graph) : Prop :=
  (forall e, In e (g_edges g) ->
    dir_exists g (ce_dir e) /\ inode_exists g (ce_ino e)) /\
  NoDupInodeIds g /\
  NoDupDirIds g.

(* --- 5.2 LinkCountConsistent ---                                       *)
(* For every inode i, link_count(i) = |{e in edges | e.ino = i /\ e.name <> ".."}| *)
(* This is TLA+'s LinkCountConsistent.                                    *)

Definition LinkCountConsistent (g : Graph) : Prop :=
  forall ir, In ir (g_inodes g) ->
    ir_link_count ir = incoming_count g (ir_id ir).

(* --- 5.3 UniqueNamesPerDir ---                                         *)
(* In each directory, no two edges share the same name.                  *)
(* TLA+: forall d, forall e1 e2, e1.dir=d /\ e2.dir=d /\ e1.name=e2.name => e1=e2 *)

Definition UniqueNamesPerDir (g : Graph) : Prop :=
  forall e1 e2, In e1 (g_edges g) -> In e2 (g_edges g) ->
    ce_dir e1 = ce_dir e2 ->
    ce_name e1 = ce_name e2 ->
    e1 = e2.

(* --- 5.4 NoDanglingEdges ---                                           *)
(* Every edge has both endpoints present as nodes.                       *)
(* This is the same as the first conjunct of TypeInvariant, but we       *)
(* state it separately for clarity (mirrors TLA+ NoDanglingEdges).       *)

Definition NoDanglingEdges (g : Graph) : Prop :=
  forall e, In e (g_edges g) ->
    dir_exists g (ce_dir e) /\ inode_exists g (ce_ino e).

(* --- 5.5 NoDirCycles ---                                               *)
(* No cycle in the directory DAG (excluding "." and ".." edges).         *)
(* We formalize as: there is a well-founded ranking on directories.      *)
(* Specifically: there exists a function rank : DirId -> nat such that   *)
(* for every non-dot/dotdot contains edge from dir d to a directory      *)
(* inode i paired with dir d', rank(d') < rank(d).                       *)

Definition NoDirCycles (g : Graph) : Prop :=
  exists rank : DirId -> nat,
    forall e, In e (g_edges g) ->
      is_user_name (ce_name e) ->
      forall ir, find_inode g (ce_ino e) = Some ir ->
        ir_vtype ir = DirectoryType ->
        forall child_dir, dir_for_inode g (ce_ino e) = Some child_dir ->
          rank child_dir < rank (ce_dir e).

(* ===================================================================== *)
(* 12. Well-formed graph: conjunction of all invariants                   *)
(* ===================================================================== *)

Definition WellFormed (g : Graph) : Prop :=
  TypeInvariant g /\
  LinkCountConsistent g /\
  UniqueNamesPerDir g /\
  NoDanglingEdges g /\
  NoDirCycles g.

(* ===================================================================== *)
(* 13. Initial graph (CREATE-ROOT) — matches TLA+ Init                   *)
(* ===================================================================== *)

Definition root_inode_id : InodeId := 1.
Definition root_dir_id   : DirId := 1.

Definition init_graph : Graph := {|
  g_inodes := [mkInode root_inode_id DirectoryType 1];
  g_dirs   := [mkDir root_dir_id root_inode_id];
  g_edges  := [mkContains root_dir_id root_inode_id dot_name];
|}.

(* ===================================================================== *)
(* 14. Useful lemmas for the invariant proofs                            *)
(* ===================================================================== *)

Lemma count_occ_pred_app :
  forall {A} (f : A -> bool) l1 l2,
    count_occ_pred f (l1 ++ l2) = count_occ_pred f l1 + count_occ_pred f l2.
Proof.
  intros A f l1. induction l1 as [|x xs IH]; simpl; intro l2.
  - reflexivity.
  - rewrite IH. lia.
Qed.

Lemma count_occ_pred_cons_true :
  forall {A} (f : A -> bool) x xs,
    f x = true ->
    count_occ_pred f (x :: xs) = S (count_occ_pred f xs).
Proof.
  intros. simpl. rewrite H. simpl. reflexivity.
Qed.

Lemma count_occ_pred_cons_false :
  forall {A} (f : A -> bool) x xs,
    f x = false ->
    count_occ_pred f (x :: xs) = count_occ_pred f xs.
Proof.
  intros. simpl. rewrite H. simpl. reflexivity.
Qed.

(* NoDup for appended lists — our own version for portability *)
Lemma NoDup_app_intro :
  forall {A : Type} (l1 l2 : list A),
    NoDup l1 ->
    NoDup l2 ->
    (forall x, In x l1 -> ~ In x l2) ->
    NoDup (l1 ++ l2).
Proof.
  intros A l1 l2 Hnd1 Hnd2 Hdisj.
  induction l1 as [|a l1' IH].
  - simpl. exact Hnd2.
  - simpl. constructor.
    + rewrite in_app_iff. intros [H1 | H2].
      * inversion Hnd1. contradiction.
      * apply (Hdisj a). { left. reflexivity. } exact H2.
    + apply IH.
      * inversion Hnd1. exact H2.
      * intros x Hin. apply Hdisj. right. exact Hin.
Qed.

(* find over appended lists *)
Lemma find_app_iff :
  forall {A : Type} (f : A -> bool) (l1 l2 : list A),
    find f (l1 ++ l2) =
    match find f l1 with
    | Some x => Some x
    | None => find f l2
    end.
Proof.
  intros A f l1. induction l1 as [|x xs IH]; intro l2.
  - simpl. reflexivity.
  - simpl. destruct (f x).
    + reflexivity.
    + apply IH.
Qed.

(* Helper: the init_graph is well-formed *)
Lemma init_graph_well_formed : WellFormed init_graph.
Proof.
  unfold WellFormed, init_graph. simpl.
  repeat split.
  (* TypeInvariant *)
  - (* edges endpoints exist *)
    intros e Hin.
    destruct Hin as [He | []]. subst e. simpl.
    split; left; reflexivity.
  - (* NoDupInodeIds *)
    unfold NoDupInodeIds, inode_ids. simpl.
    constructor. { simpl. auto. } constructor.
  - (* NoDupDirIds *)
    unfold NoDupDirIds, dir_ids. simpl.
    constructor. { simpl. auto. } constructor.
  - (* LinkCountConsistent *)
    intros ir Hin.
    destruct Hin as [Hir | []]. subst ir. simpl.
    reflexivity.
  - (* UniqueNamesPerDir *)
    intros e1 e2 Hin1 Hin2 Hdir Hname.
    destruct Hin1 as [He1 | []]; destruct Hin2 as [He2 | []];
    subst; reflexivity.
  - (* NoDanglingEdges *)
    intros e Hin.
    destruct Hin as [He | []]. subst e. simpl.
    split; left; reflexivity.
  - (* NoDirCycles *)
    exists (fun _ => 0).
    intros e Hin Huser ir Hfind Htype child_dir Hchild.
    destruct Hin as [He | []]. subst e.
    (* The only edge is dot_name = 0, which is not a user name (>= 2) *)
    unfold is_user_name in Huser. unfold dot_name in Huser. lia.
Qed.

(* ===================================================================== *)
(* 15. Decidability lemmas used across DPO modules                       *)
(* ===================================================================== *)

Lemma name_in_dir_false_not_in :
  forall g d n,
    name_in_dir g d n = false ->
    ~(exists ino, In (mkContains d ino n) (g_edges g)).
Proof.
  unfold name_in_dir.
  intros g d n Hfalse [ino Hin].
  assert (Hcontra : existsb
    (fun e => Nat.eqb (ce_dir e) d && Nat.eqb (ce_name e) n)
    (g_edges g) = true).
  { apply existsb_exists.
    exists (mkContains d ino n). split. exact Hin.
    simpl. rewrite Nat.eqb_refl. rewrite Nat.eqb_refl. reflexivity. }
  rewrite Hfalse in Hcontra. discriminate.
Qed.

Lemma not_in_edges_incoming_zero :
  forall edges ino,
    (forall e, In e edges -> ce_ino e <> ino) ->
    count_occ_pred
      (fun e => Nat.eqb (ce_ino e) ino && negb (Nat.eqb (ce_name e) dotdot_name))
      edges = 0.
Proof.
  induction edges as [|e es IH]; intros ino Hnotin.
  - reflexivity.
  - simpl. destruct (Nat.eqb (ce_ino e) ino) eqn:Heq.
    + apply Nat.eqb_eq in Heq.
      exfalso. apply (Hnotin e). { left. reflexivity. } exact Heq.
    + simpl. apply IH. intros e' Hin'.
      apply Hnotin. right. exact Hin'.
Qed.

(* remove_edge preserves membership of other elements *)
Lemma remove_edge_subset :
  forall e edges x,
    In x (remove_edge e edges) -> In x edges.
Proof.
  intros e edges. induction edges as [|h t IH]; intros x Hin.
  - simpl in Hin. contradiction.
  - simpl in Hin. destruct (ce_eqb h e) eqn:Heq.
    + right. exact Hin.
    + simpl in Hin. destruct Hin as [Hh | Ht].
      * left. exact Hh.
      * right. apply IH. exact Ht.
Qed.

Lemma remove_edge_preserves :
  forall e edges x,
    In x edges -> x <> e -> In x (remove_edge e edges).
Proof.
  intros e edges. induction edges as [|h t IH]; intros x Hin Hneq.
  - contradiction.
  - simpl. destruct (ce_eqb h e) eqn:Heq.
    + destruct Hin as [Hh | Ht].
      * apply ce_eqb_eq in Heq. subst. contradiction.
      * exact Ht.
    + simpl. destruct Hin as [Hh | Ht].
      * left. exact Hh.
      * right. apply IH; assumption.
Qed.
