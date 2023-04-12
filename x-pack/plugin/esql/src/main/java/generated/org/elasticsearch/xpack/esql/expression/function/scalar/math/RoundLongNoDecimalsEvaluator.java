// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License
// 2.0; you may not use this file except in compliance with the Elastic License
// 2.0.
package org.elasticsearch.xpack.esql.expression.function.scalar.math;

import java.lang.Long;
import java.lang.Object;
import java.lang.Override;
import java.lang.String;
import org.elasticsearch.compute.data.Page;
import org.elasticsearch.compute.operator.EvalOperator;
import org.elasticsearch.xpack.ql.expression.Expression;

/**
 * {@link EvalOperator.ExpressionEvaluator} implementation for {@link Round}.
 * This class is generated. Do not edit it.
 */
public final class RoundLongNoDecimalsEvaluator implements EvalOperator.ExpressionEvaluator {
  private final EvalOperator.ExpressionEvaluator val;

  public RoundLongNoDecimalsEvaluator(EvalOperator.ExpressionEvaluator val) {
    this.val = val;
  }

  static Long fold(Expression val) {
    Object valVal = val.fold();
    if (valVal == null) {
      return null;
    }
    return Round.process((long) valVal);
  }

  @Override
  public Object computeRow(Page page, int position) {
    Object valVal = val.computeRow(page, position);
    if (valVal == null) {
      return null;
    }
    return Round.process((long) valVal);
  }

  @Override
  public String toString() {
    return "RoundLongNoDecimalsEvaluator[" + "val=" + val + "]";
  }
}
