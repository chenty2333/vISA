use super::*;

impl SemanticGraph {
    pub fn begin_transaction(
        &mut self,
        label: &str,
        store: Option<StoreId>,
        task: Option<TaskId>,
    ) -> TransactionId {
        let id = self.domains.lifecycle.next_transaction_id;
        self.domains.lifecycle.next_transaction_id += 1;
        self.domains.lifecycle.transactions.push(SemanticTransactionRecord {
            id,
            label: label.to_string(),
            store,
            task,
            state: TransactionState::Begun,
            generation: 1,
        });
        self.event_log.push(
            "transaction",
            EventKind::TransactionBegan { transaction: id, store, task, label: label.to_string() },
        );
        id
    }
    pub fn commit_transaction(&mut self, id: TransactionId) {
        let Some(transaction) =
            self.domains.lifecycle.transactions.iter_mut().find(|transaction| transaction.id == id)
        else {
            return;
        };
        if transaction.state != TransactionState::Begun {
            return;
        }
        transaction.state = TransactionState::Committed;
        transaction.generation += 1;
        self.event_log.push(
            "transaction",
            EventKind::TransactionCommitted { transaction: id, generation: transaction.generation },
        );
    }
    pub fn rollback_transaction(&mut self, id: TransactionId, reason: &str) {
        let Some(transaction) =
            self.domains.lifecycle.transactions.iter_mut().find(|transaction| transaction.id == id)
        else {
            return;
        };
        if transaction.state != TransactionState::Begun {
            return;
        }
        transaction.state = TransactionState::RolledBack;
        transaction.generation += 1;
        self.event_log.push(
            "transaction",
            EventKind::TransactionRolledBack {
                transaction: id,
                reason: reason.to_string(),
                generation: transaction.generation,
            },
        );
    }
    pub fn install_fast_path_plan(
        &mut self,
        subject: &str,
        object: &str,
        operation: &str,
    ) -> PlanId {
        let id = self.domains.lifecycle.next_plan_id;
        self.domains.lifecycle.next_plan_id += 1;
        self.domains.lifecycle.fast_path_plans.push(FastPathPlanRecord {
            id,
            subject: subject.to_string(),
            object: object.to_string(),
            operation: operation.to_string(),
            generation: 1,
            valid: true,
        });
        self.event_log.push("fastpath", EventKind::FastPathPlanInstalled { plan: id });
        id
    }
    pub fn invalidate_fast_path_plan(&mut self, id: PlanId) {
        let Some(plan) =
            self.domains.lifecycle.fast_path_plans.iter_mut().find(|plan| plan.id == id)
        else {
            return;
        };
        if !plan.valid {
            return;
        }
        plan.valid = false;
        plan.generation += 1;
        self.event_log.push("fastpath", EventKind::FastPathPlanInvalidated { plan: id });
    }
    pub fn record_failure_effect(&mut self, effect: FailureEffect) {
        self.event_log.push("failure", EventKind::FailureEffect { effect });
    }
    pub fn transaction_count(&self) -> usize {
        self.domains.lifecycle.transactions.len()
    }
    pub fn fast_path_plan_count(&self) -> usize {
        self.domains.lifecycle.fast_path_plans.len()
    }
    pub fn active_fast_path_plan_count(&self) -> usize {
        self.domains.lifecycle.fast_path_plans.iter().filter(|plan| plan.valid).count()
    }
    pub fn active_transaction_count(&self) -> usize {
        self.domains
            .lifecycle
            .transactions
            .iter()
            .filter(|transaction| transaction.state == TransactionState::Begun)
            .count()
    }
    pub fn transactions(&self) -> &[SemanticTransactionRecord] {
        &self.domains.lifecycle.transactions
    }
    pub fn fast_path_plans(&self) -> &[FastPathPlanRecord] {
        &self.domains.lifecycle.fast_path_plans
    }
}
