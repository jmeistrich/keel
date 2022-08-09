import {
  sql,
  ValueExpression,
  TaggedTemplateLiteralInvocation
} from 'slonik';
import {
  BuiltInFields,
  Conditions,
  Constraints
} from '../types';

const ENDS_WITH = 'endsWith';
const CONTAINS = 'contains';
const STARTS_WITH = 'startsWith';
const ONE_OF = 'oneOf';
const GREATER_THAN = 'greaterThan';
const LESS_THAN = 'lessThan';
const GREATER_THAN_OR_EQUAL_TO = 'greaterThanOrEqualTo';
const LESS_THAN_OR_EQUAL_TO = 'lessThanOrEqualTo';

export const buildSelectStatement = <T>(tableName: string, conditions: Conditions<T>[]) : TaggedTemplateLiteralInvocation<T> => {
  const ands : ValueExpression[] = [];
  const hasConditions = conditions.length > 0;
  const baseQuery = sql`SELECT * FROM ${sql.identifier([tableName])}`;

  if (hasConditions) {
    conditions.forEach((condition) => {
      const ors : ValueExpression[] = [];
  
      Object.entries(condition).forEach(([field, constraints]) => {
        const isComplex = isComplexConstraint(constraints);
  
        if (isComplex) {
          Object.entries(constraints).forEach(([operation, value]) => {
            switch(operation) {
            case STARTS_WITH:
              ors.push(sql`${field} ILIKE '${value}%'`);
              break;
            case ENDS_WITH:
              ors.push(sql`${field} ILIKE '%${value}'`);
              break;
            case CONTAINS:
              ors.push(sql`${field} ILIKE '%${value}%'`);
              break;
            case ONE_OF:
              // todo: join with correct type
              if (Array.isArray(value) && value.length > 0) {
                ors.push(sql`${field} IN (${sql.join(value, sql`,`)})`);
              }
              break;
            case GREATER_THAN:
              ors.push(sql`${field} > ${value}`);
              break;
            case LESS_THAN:
              ors.push(sql`${field} < ${value}`);
              break;
            case LESS_THAN_OR_EQUAL_TO:
              ors.push(sql`${field} <= ${value}`);
              break;
            case GREATER_THAN_OR_EQUAL_TO:
              ors.push(sql`${field} >= ${value}`);
              break;
            }
          });
        } else {
          ors.push(sql`${sql.identifier([field])} = ${constraints as ValueExpression}`);
        }
      });
  
      const s = sql.join(ors, sql` AND `);
  
      // group with ()
      const grouping = sql`(${s})`;
  
      ands.push(grouping);
    });

    const whereSqlToken = sql.join(ands, sql` OR `);
  
    return sql`${baseQuery} WHERE ${whereSqlToken}`;
  }

  return baseQuery; 
};

const isComplexConstraint = (constraint: Constraints): boolean => {
  return constraint instanceof Object && constraint.constructor === Object;
};

export const buildCreateStatement = <T>(tableName: string, inputs: Partial<T>, builtInFields: BuiltInFields) : TaggedTemplateLiteralInvocation => {
  const values = [];
  const cols = [];

  //  const query = import_slonik.sql`INSERT INTO ${import_slonik.sql.identifier([tableName])} (${import_slonik.sql.}) VALUES (${import_slonik.}) RETURNING id`;
  
  // todo: make below less undesirable
  Object.entries(inputs).forEach(([key, value]) => {
    cols.push(key);
    values.push(value);
  });

  Object.entries(builtInFields).forEach(([key, value]) => {
    cols.push(key);
    values.push(value);
  });

  return sql`
    INSERT INTO ${sql.identifier([tableName])} (${sql.join(Object.keys(inputs).map(f => sql.identifier([f])), sql`, `)})
    VALUES (${sql.join(Object.values(inputs), sql`, `)})
    RETURNING id`;
};

export const buildUpdateStatement = <T>(tableName: string, id: string, inputs: Partial<T>) : TaggedTemplateLiteralInvocation<T> => {
  const values = Object.entries(inputs).map(([key, value]) => {
    return sql`${key} = ${value as any}`;
  });

  const query = sql`UPDATE ${sql.identifier([tableName])} SET ${sql.join(values, sql`,`)} WHERE id = ${id}`;

  return query;
};

export const buildDeleteStatement = <T>(tableName: string, id: string) : TaggedTemplateLiteralInvocation<T> => {
  const query = sql`DELETE FROM ${sql.identifier([tableName])} WHERE id = ${id} RETURNING id`;

  return query;
};
