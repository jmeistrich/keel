package node

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teamkeel/keel/codegen"
	"github.com/teamkeel/keel/colors"
	"github.com/teamkeel/keel/proto"
	"github.com/teamkeel/keel/schema"
	"github.com/teamkeel/keel/testhelpers"
)

const testSchema = `
enum Gender {
	Male
	Female
}

model Person {
	fields {
		firstName Text @unique
		lastName Text?
		age Number
		dateOfBirth Date
		gender Gender
		hasChildren Boolean
	}
}`

func TestWriteTableInterface(t *testing.T) {
	expected := `
export interface PersonTable {
	firstName: string
	lastName: string | null
	age: number
	dateOfBirth: Date
	gender: Gender
	hasChildren: boolean
	id: Generated<string>
	createdAt: Generated<Date>
	updatedAt: Generated<Date>
}
`
	runWriterTest(t, testSchema, expected, func(s *proto.Schema, w *codegen.Writer) {
		m := proto.FindModel(s.Models, "Person")
		writeTableInterface(w, m)
	})
}

func TestWriteModelInterface(t *testing.T) {
	expected := `
export interface Person {
	firstName: string
	lastName: string | null
	age: number
	dateOfBirth: Date
	gender: Gender
	hasChildren: boolean
	id: string
	createdAt: Date
	updatedAt: Date
}
`
	runWriterTest(t, testSchema, expected, func(s *proto.Schema, w *codegen.Writer) {
		m := proto.FindModel(s.Models, "Person")
		writeModelInterface(w, m)
	})
}

func TestWriteCreateValuesInterface(t *testing.T) {
	expected := `
export interface PersonCreateValues {
	firstName: string
	lastName?: string | null
	age: number
	dateOfBirth: Date
	gender: Gender
	hasChildren: boolean
	id?: string
	createdAt?: Date
	updatedAt?: Date
}
`
	runWriterTest(t, testSchema, expected, func(s *proto.Schema, w *codegen.Writer) {
		m := proto.FindModel(s.Models, "Person")
		writeCreateValuesInterface(w, m)
	})
}

func TestWriteCreateValuesInterfaceWithRelationships(t *testing.T) {
	schema := `
model Author {}
model Post {
	fields {
		author Author
	}
}`

	expected := `
export interface PostCreateValues {
	id?: string
	createdAt?: Date
	updatedAt?: Date
	authorId: string
}
`
	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		m := proto.FindModel(s.Models, "Post")
		writeCreateValuesInterface(w, m)
	})
}

func TestWriteWhereConditionsInterface(t *testing.T) {
	expected := `
export interface PersonWhereConditions {
	firstName?: string | runtime.StringWhereCondition;
	lastName?: string | runtime.StringWhereCondition | null;
	age?: number | runtime.NumberWhereCondition;
	dateOfBirth?: Date | runtime.DateWhereCondition;
	gender?: Gender | GenderWhereCondition;
	hasChildren?: boolean | runtime.BooleanWhereCondition;
	id?: string | runtime.IDWhereCondition;
	createdAt?: Date | runtime.DateWhereCondition;
	updatedAt?: Date | runtime.DateWhereCondition;
}`
	runWriterTest(t, testSchema, expected, func(s *proto.Schema, w *codegen.Writer) {
		m := proto.FindModel(s.Models, "Person")
		writeWhereConditionsInterface(w, m)
	})
}

func TestWriteUniqueConditionsInterface(t *testing.T) {
	schema := `
	model Author {
		fields {
			books Book[]
		}
	}
	model Book {
		fields {
			title Text @unique
			author Author
		}
	}
	`

	// You can't find a single book by author, because an author
	// writes many books
	expectedBookType := `
export type BookUniqueConditions = 
	| {title: string}
	| {id: string};
	`

	// You can find a single author by a book, because a book
	// is written by a single author. So we include the
	// BookUniqueConditions type within AuthorUniqueConditions
	expectedAuthorType := `
export type AuthorUniqueConditions = 
	| {books: BookUniqueConditions}
	| {id: string};
	`

	runWriterTest(t, schema, expectedBookType, func(s *proto.Schema, w *codegen.Writer) {
		m := proto.FindModel(s.Models, "Book")
		writeUniqueConditionsInterface(w, m)
	})

	runWriterTest(t, schema, expectedAuthorType, func(s *proto.Schema, w *codegen.Writer) {
		m := proto.FindModel(s.Models, "Author")
		writeUniqueConditionsInterface(w, m)
	})
}

func TestWriteModelAPIDeclaration(t *testing.T) {
	expected := fmt.Sprintf(`
export type PersonAPI = {
	/**
	* Create a Person record
	* @example
	%[1]stypescript
	const record = await models.person.create({
		firstName: '',
		age: 0,
		dateOfBirth: new Date(),
		gender: undefined,
		hasChildren: false
	});
	%[1]s
	*/
	create(values: PersonCreateValues): Promise<Person>;
	/**
	* Update a Person record
	* @example
	%[1]stypescript
	const person = await models.person.update({ id: "abc" }, { firstName: XXX }});
	%[1]s
	*/
	update(where: PersonUniqueConditions, values: Partial<Person>): Promise<Person>;
	/**
	* Deletes a Person record
	* @example
	%[1]stypescript
	const deletedId = await models.person.delete({ id: 'xxx' });
	%[1]s
	*/
	delete(where: PersonUniqueConditions): Promise<string>;
	/**
	* Finds a single Person record
	* @example
	%[1]stypescript
	const person = await models.person.findOne({ id: 'xxx' });
	%[1]s
	*/
	findOne(where: PersonUniqueConditions): Promise<Person | null>;
	/**
	* Finds multiple Person records
	* @example
	%[1]stypescript
	const persons = await models.person.findMany({ where: { createdAt: { after: new Date(2022, 1, 1) } }, orderBy: { id: 'asc' }, limit: 1000, offset: 50 });
	%[1]s
	*/
	findMany(params?: PersonFindManyParams | undefined): Promise<Person[]>;
	/**
	* Creates a new query builder with the given conditions applied
	* @example
	%[1]stypescript
	const records = await models.person.where({ createdAt: { after: new Date(2020, 1, 1) } }).orWhere({ updatedAt: { after: new Date(2020, 1, 1) } }).findMany();
	%[1]s
	*/
	where(where: PersonWhereConditions): PersonQueryBuilder;
}`, "```", "`")

	runWriterTest(t, testSchema, expected, func(s *proto.Schema, w *codegen.Writer) {
		m := proto.FindModel(s.Models, "Person")
		writeModelAPIDeclaration(w, m)
	})
}

func TestModelAPIFindManyDeclaration(t *testing.T) {
	expected := `
export type PersonOrderBy = {
	firstName?: SortDirection,
	lastName?: SortDirection,
	age?: SortDirection,
	dateOfBirth?: SortDirection,
	gender?: SortDirection,
	hasChildren?: SortDirection,
	id?: SortDirection,
	createdAt?: SortDirection,
	updatedAt?: SortDirection
}

export interface PersonFindManyParams {
	where?: PersonWhereConditions;
	limit?: number;
	offset?: number;
	orderBy?: PersonOrderBy;
}`

	runWriterTest(t, testSchema, expected, func(s *proto.Schema, w *codegen.Writer) {
		m := proto.FindModel(s.Models, "Person")
		writeFindManyParamsInterface(w, m, false)
	})
}

func TestWriteEnum(t *testing.T) {
	expected := `
export enum Gender {
	Male = "Male",
	Female = "Female",
}`

	runWriterTest(t, testSchema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeEnum(w, s.Enums[0])
	})
}

func TestWriteEnumWhereCondition(t *testing.T) {
	expected := `
export interface GenderWhereCondition {
	equals?: Gender | null;
	oneOf?: Gender[] | null;
}`

	runWriterTest(t, testSchema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeEnumWhereCondition(w, s.Enums[0])
	})
}

func TestWriteDatabaseInterface(t *testing.T) {
	expected := `
interface database {
	person: PersonTable;
	identity: IdentityTable;
}
export declare function useDatabase(): Kysely<database>;`

	runWriterTest(t, testSchema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeDatabaseInterface(w, s)
	})
}

func TestWriteDevelopmentServer(t *testing.T) {
	expected := `
import function_createPost from "../functions/createPost.ts";
import function_updatePost from "../functions/updatePost.ts";
import job_batchPosts from "../jobs/batchPosts.ts";
import subscriber_checkGrammar from "../subscribers/checkGrammar.ts";
const functions = {
	createPost: function_createPost,
	updatePost: function_updatePost,
}
const jobs = {
	batchPosts: job_batchPosts,
}
const subscribers = {
	checkGrammar: subscriber_checkGrammar,
}
const actionTypes = {
	createPost: "ACTION_TYPE_CREATE",
	updatePost: "ACTION_TYPE_UPDATE",
}
	`

	schema := `
model Post {
	fields {
		title Text
	}

	actions {
		create createPost() with(title) @function
		update updatePost(id) with(title) @function
	}

	@on([create], checkGrammar)
}

job BatchPosts {
	@schedule("* * * * *")
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		files := generateDevelopmentServer(s)

		serverJs := files[0]

		w.Write(serverJs.Contents)
	})
}

func TestWriteAPIFactory(t *testing.T) {
	expected := `
function createContextAPI({ responseHeaders, meta }) {
	const headers = new runtime.RequestHeaders(meta.headers);
	const response = { headers: responseHeaders }
	const now = () => { return new Date(); };
	const { identity } = meta;
	const isAuthenticated = identity != null;
	const env = {
		TEST: process.env["TEST"] || "",
	};
	const secrets = {
		SECRET_KEY: meta.secrets.SECRET_KEY || "",
	};
	return { headers, response, identity, env, now, secrets, isAuthenticated };
};
function createJobContextAPI({ meta }) {
	const now = () => { return new Date(); };
	const { identity } = meta;
	const isAuthenticated = identity != null;
	const env = {
		TEST: process.env["TEST"] || "",
	};
	const secrets = {
		SECRET_KEY: meta.secrets.SECRET_KEY || "",
	};
	return { identity, env, now, secrets, isAuthenticated };
};
function createSubscriberContextAPI({ meta }) {
	const now = () => { return new Date(); };
	const env = {
		TEST: process.env["TEST"] || "",
	};
	const secrets = {
		SECRET_KEY: meta.secrets.SECRET_KEY || "",
	};
	return { env, now, secrets };
};
function createModelAPI() {
	return {
		person: new runtime.ModelAPI("person", () => ({}), tableConfigMap),
		identity: new runtime.ModelAPI("identity", () => ({}), tableConfigMap),
	};
};
function createPermissionApi() {
	return new runtime.Permissions();
};
module.exports.models = createModelAPI();
module.exports.permissions = createPermissionApi();
module.exports.createContextAPI = createContextAPI;
module.exports.createJobContextAPI = createJobContextAPI;
module.exports.createSubscriberContextAPI = createSubscriberContextAPI;`

	runWriterTest(t, testSchema, expected, func(s *proto.Schema, w *codegen.Writer) {
		s.EnvironmentVariables = append(s.EnvironmentVariables, &proto.EnvironmentVariable{
			Name: "TEST",
		})
		s.Secrets = append(s.Secrets, &proto.Secret{
			Name: "SECRET_KEY",
		})

		writeAPIFactory(w, s)
	})
}

func TestWriteAPIDeclarations(t *testing.T) {
	expected := `
export type ModelsAPI = {
	person: PersonAPI;
	identity: IdentityAPI;
}
export declare const models: ModelsAPI;
export declare const permissions: runtime.Permissions;
type Environment = {
	TEST: string;
}
type Secrets = {
	SECRET_KEY: string;
}

export interface ContextAPI extends runtime.ContextAPI {
	secrets: Secrets;
	env: Environment;
	identity?: Identity;
	now(): Date;
}
export interface JobContextAPI {
	secrets: Secrets;
	env: Environment;
	identity?: Identity;
	now(): Date;
}`

	runWriterTest(t, testSchema, expected, func(s *proto.Schema, w *codegen.Writer) {
		s.EnvironmentVariables = append(s.EnvironmentVariables, &proto.EnvironmentVariable{
			Name: "TEST",
		})
		s.Secrets = append(s.Secrets, &proto.Secret{
			Name: "SECRET_KEY",
		})

		writeAPIDeclarations(w, s)
	})
}

func TestWriteActionInputTypesGet(t *testing.T) {
	schema := `
model Person {
	actions {
		get getPerson(id) @function
	}
}
	`
	expected := `
export interface GetPersonInput {
	id: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesCreate(t *testing.T) {
	schema := `
model Person {
	fields {
		name Text
	}
	actions {
		create createPerson() with (name) @function
	}
}
	`
	expected := `
export interface CreatePersonInput {
	name: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesCreateWithNull(t *testing.T) {
	schema := `
model Person {
	fields {
		name Text?
	}
	actions {
		create createPerson() with (name) @function
	}
}
	`
	expected := `
export interface CreatePersonInput {
	name: string | null;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesCreateWithOptionalInput(t *testing.T) {
	schema := `
model Person {
	fields {
		name Text?
	}
	actions {
		create createPerson() with (name?) @function
	}
}`

	expected := `
export interface CreatePersonInput {
	name?: string | null;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesCreateRelationshipToOne(t *testing.T) {
	schema := `
model Company {
	fields {
		name Text
	}
}
model Person {
	fields {
		name Text
		employer Company
	}
	actions {
		create createPerson() with (name, employer.name) @function
	}
}`

	expected := `
export interface CreatePersonInput {
	name: string;
	employer: CreatePersonEmployerInput;
}
export interface CreatePersonEmployerInput {
	name: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesCreateRelationshipToMany(t *testing.T) {
	schema := `
model Contract {
	fields {
		name Text
		person Person
	}
}
model Person {
	fields {
		name Text
		contracts Contract[]
	}
	actions {
		create createPerson() with (name, contracts.name) @function
	}
}`

	expected := `
export interface CreatePersonInput {
	name: string;
	contracts: CreatePersonContractsInput[];
}
export interface CreatePersonContractsInput {
	name: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesCreateRelationshipOneToOne(t *testing.T) {
	schema := `
model Company {
	fields {
		name Text
		companyProfile CompanyProfile @unique
	}

	actions {
		create createCompany() with (
			name,
			companyProfile.employeeCount,
			companyProfile.taxProfile.taxNumber,
		)
	}
}

model CompanyProfile {
	fields {
		employeeCount Number
		taxProfile TaxProfile? @unique
		company Company
	}
}

model TaxProfile {
	fields {
		taxNumber Text
		companyProfile CompanyProfile
	}
}`

	expected := `
export interface CreateCompanyInput {
	name: string;
	companyProfile: CreateCompanyCompanyProfileInput;
}
export interface CreateCompanyCompanyProfileInput {
	employeeCount: number;
	taxProfile: CreateCompanyCompanyProfileTaxProfileInput | null;
}
export interface CreateCompanyCompanyProfileTaxProfileInput {
	taxNumber: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestCreateActionEmptyInputs(t *testing.T) {
	schema := `
model Account {
    fields {
        name Text?
        email Text
    }

    actions {
        create createAccount() {
            @set(account.email = ctx.identity.email)
        }
    }
}

api Test {
    models {
        Account
    }
}`
	expected := `
export interface CreateAccountInput {
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestCreateActionEmptyInputsTestingType(t *testing.T) {
	schema := `
model Account {
    fields {
        name Text?
        email Text
    }

    actions {
        create createAccount() {
            @set(account.email = ctx.identity.email)
        }
    }
}

api Test {
    models {
        Account
    }
}`
	expected := `
createAccount(i?: CreateAccountInput): Promise<sdk.Account>;`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeTestingTypes(w, s)
	})

}

func TestWriteActionInputTypesUpdate(t *testing.T) {
	schema := `
model Person {
	fields {
		name Text
	}
	actions {
		update updatePerson(id) with (name) @function
	}
}
	`
	expected := `
export interface UpdatePersonWhere {
	id: string;
}
export interface UpdatePersonValues {
	name: string;
}
export interface UpdatePersonInput {
	where: UpdatePersonWhere;
	values: UpdatePersonValues;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesUpdateWithOptionalField(t *testing.T) {
	schema := `
model Person {
	fields {
		name Text?
	}
	actions {
		update updatePerson(id) with (name) @function
	}
}
	`
	expected := `
export interface UpdatePersonWhere {
	id: string;
}
export interface UpdatePersonValues {
	name: string | null;
}
export interface UpdatePersonInput {
	where: UpdatePersonWhere;
	values: UpdatePersonValues;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesUpdateWithOptionalFieldAndOptionalInput(t *testing.T) {
	schema := `
model Person {
	fields {
		name Text?
	}
	actions {
		update updatePerson(id) with (name?) @function
	}
}
	`
	expected := `
export interface UpdatePersonWhere {
	id: string;
}
export interface UpdatePersonValues {
	name?: string | null;
}
export interface UpdatePersonInput {
	where: UpdatePersonWhere;
	values?: UpdatePersonValues;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesList(t *testing.T) {
	schema := `
model Person {
	fields {
		name Text
	}
	actions {
		list listPeople(name, some: Boolean?) @function
	}
}
	`
	expected := `
export interface StringQueryInput {
	equals?: string | null;
	notEquals?: string | null;
	startsWith?: string;
	endsWith?: string;
	contains?: string;
	oneOf?: string[];
}
export interface ListPeopleWhere {
	name: StringQueryInput;
	some?: boolean;
}
export interface ListPeopleInput {
	where: ListPeopleWhere;
	first?: number;
	after?: string;
	last?: number;
	before?: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesListAction(t *testing.T) {
	schema := `
enum Sport {
	Football
	Tennis
}
model Person {
	fields {
		name Text
		favouriteSport Sport
	}
	actions {
		list listPeople(name, favouriteSport)
	}
}
	`
	expected := `
export interface StringQueryInput {
	equals?: string | null;
	notEquals?: string | null;
	startsWith?: string;
	endsWith?: string;
	contains?: string;
	oneOf?: string[];
}
export interface SportQueryInput {
	equals?: Sport | null;
	notEquals?: Sport | null;
	oneOf?: Sport[];
}
export interface ListPeopleWhere {
	name: StringQueryInput;
	favouriteSport: SportQueryInput;
}
export interface ListPeopleInput {
	where: ListPeopleWhere;
	first?: number;
	after?: string;
	last?: number;
	before?: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesListRelationshipToOne(t *testing.T) {
	schema := `
model Company {
	fields {
		name Text
	}
}
model Person {
	fields {
		name Text
		employer Company
	}
	actions {
		list listPersons(name, employer.name) @function
	}
}`

	expected := `
export interface ListPersonsEmployerInput {
	name: StringQueryInput;
}
export interface ListPersonsWhere {
	name: StringQueryInput;
	employer: ListPersonsEmployerInput;
}
export interface ListPersonsInput {
	where: ListPersonsWhere;
	first?: number;
	after?: string;
	last?: number;
	before?: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesListRelationshipToMany(t *testing.T) {
	schema := `
model Contract {
	fields {
		name Text
	}
}
model Person {
	fields {
		name Text
		contracts Contract
	}
	actions {
		list listPersons(name, contracts.name) @function
	}
}`

	expected := `
export interface ListPersonsContractsInput {
	name: StringQueryInput;
}
export interface ListPersonsWhere {
	name: StringQueryInput;
	contracts: ListPersonsContractsInput;
}
export interface ListPersonsInput {
	where: ListPersonsWhere;
	first?: number;
	after?: string;
	last?: number;
	before?: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesListRelationshipOptionalFields(t *testing.T) {
	schema := `
	model Publisher {
		fields {
			name Text?
			authors Author[]
		}
	
	}
	
	model Author {
		fields {
			publisher Publisher?
			books Book[]
		}
	}
	
	model Book {
		fields {
			author Author?
		}
	
		actions {
			list listBooks(author.publisher.name) @function
		}
	}`

	expected := `
export interface ListBooksAuthorInput {
	publisher: ListBooksAuthorPublisherInput;
}
export interface ListBooksAuthorPublisherInput {
	name: StringQueryInput;
}
export interface StringQueryInput {
	equals?: string | null;
	notEquals?: string | null;
	startsWith?: string;
	endsWith?: string;
	contains?: string;
	oneOf?: string[];
}
export interface ListBooksWhere {
	author: ListBooksAuthorInput;
}
export interface ListBooksInput {
	where: ListBooksWhere;
	first?: number;
	after?: string;
	last?: number;
	before?: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesListRelationshipOptionalInput(t *testing.T) {
	schema := `
	model Publisher {
		fields {
			name Text
			authors Author[]
		}
	
	}
	
	model Author {
		fields {
			publisher Publisher
			books Book[]
		}
	}
	
	model Book {
		fields {
			author Author
		}
	
		actions {
			list listBooks(author.publisher.name?) @function
		}
	}`

	expected := `
export interface ListBooksAuthorInput {
	publisher?: ListBooksAuthorPublisherInput;
}
export interface ListBooksAuthorPublisherInput {
	name?: StringQueryInput;
}
export interface StringQueryInput {
	equals?: string | null;
	notEquals?: string | null;
	startsWith?: string;
	endsWith?: string;
	contains?: string;
	oneOf?: string[];
}
export interface ListBooksWhere {
	author?: ListBooksAuthorInput;
}
export interface ListBooksInput {
	where?: ListBooksWhere;
	first?: number;
	after?: string;
	last?: number;
	before?: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesListSortable(t *testing.T) {
	schema := `
enum Sport {
	Football
	Tennis
}
model Person {
	fields {
		name Text
		favouriteSport Sport
	}
	actions {
		list listPeople(name, favouriteSport) {
			@sortable(name, favouriteSport)
		}
	}
}`

	expected := `
export interface StringQueryInput {
	equals?: string | null;
	notEquals?: string | null;
	startsWith?: string;
	endsWith?: string;
	contains?: string;
	oneOf?: string[];
}
export interface SportQueryInput {
	equals?: Sport | null;
	notEquals?: Sport | null;
	oneOf?: Sport[];
}
export interface ListPeopleWhere {
	name: StringQueryInput;
	favouriteSport: SportQueryInput;
}
export interface ListPeopleOrderByName {
	name: SortDirection;
}
export interface ListPeopleOrderByFavouriteSport {
	favouriteSport: SortDirection;
}
export interface ListPeopleInput {
	where: ListPeopleWhere;
	first?: number;
	after?: string;
	last?: number;
	before?: string;
	orderBy?: (ListPeopleOrderByName | ListPeopleOrderByFavouriteSport)[];
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesDelete(t *testing.T) {
	schema := `
model Person {
	actions {
		delete deletePerson(id) @function
	}
}
	`
	expected := `
export interface DeletePersonInput {
	id: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesInlineInputRead(t *testing.T) {
	schema := `
message PersonNameResponse {
	name Text
}

model Person {
	actions {
		read getPersonName(id) returns (PersonNameResponse) @function
	}
}`
	expected := `
export interface GetPersonNameInput {
	id: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesMessageInputRead(t *testing.T) {
	schema := `
message PersonNameResponse {
	name Text
}

message GetInput {
	id ID
}

model Person {
	actions {
		read deletePerson(GetInput) returns (PersonNameResponse) @function
	}
}
	`
	expected := `
export interface GetInput {
	id: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionResponseTypesRead(t *testing.T) {
	schema := `
message PersonNameResponse {
	name Text
}

message GetInput {
	id ID
}

model Person {
	actions {
		read deletePerson(GetInput) returns (PersonNameResponse) @function
	}
}
	`
	expected := `
export interface PersonNameResponse {
	name: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesInlineInputWrite(t *testing.T) {
	schema := `
message DeleteResponse {
	isDeleted Boolean
}

model Person {
	actions {
		write deletePerson(id) returns (DeleteResponse) @function
	}
}`
	expected := `
export interface DeletePersonInput {
	id: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesMessageInputWrite(t *testing.T) {
	schema := `
message DeleteResponse {
	isDeleted Boolean
}

message DeleteInput {
	id ID
}

model Person {
	actions {
		write deletePerson(DeleteInput) returns (DeleteResponse) @function
	}
}
	`
	expected := `
export interface DeleteInput {
	id: string;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionResponseTypesWrite(t *testing.T) {
	schema := `
message DeleteResponse {
	isDeleted Boolean
}

message DeleteInput {
	id ID
}

model Person {
	actions {
		read deletePerson(DeleteInput) returns (DeleteResponse) @function
	}
}
	`
	expected := `
export interface DeleteResponse {
	isDeleted: boolean;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesArrayField(t *testing.T) {
	schema := `
message PeopleInput {
	ids ID[]
}

message People {
	names Text[]
}

model Person {
	actions {
		read readPerson(PeopleInput) returns (People) @function
	}
}`
	expected := `
export interface PeopleInput {
	ids: string[];
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestMessageFieldAnyType(t *testing.T) {
	schema := `
	message Foo {
		bar Any
	}

	model Person {
		actions {
			read getPerson(Foo) returns(Foo)
		}
	}
	`
	expected := `
export interface Foo {
    bar: any;
}
	`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionTypesEnumField(t *testing.T) {
	schema := `
message Input {
	sports Sport[]
	favouriteSport Sport?
}

message Response {
	sports Sport[]
	favouriteSport Sport?
}

model Person {
	actions {
		write writeSportInterests(Input) returns (Response) @function
	}
}

enum Sport {
	Cricket
	Rugby
	Soccer
}`
	inputExpected := `
export interface Input {
	sports: Sport[];
	favouriteSport?: Sport | null;
}`
	responseExpected := `
export interface Response {
	sports: Sport[];
	favouriteSport?: Sport | null;
}`

	runWriterTest(t, schema, inputExpected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})

	runWriterTest(t, schema, responseExpected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionResponseTypesArrayField(t *testing.T) {
	schema := `
message People {
	names Text[]
}

model Person {
	actions {
		read readPerson(name: Text) returns (People) @function
	}
}`
	expected := `
export interface People {
	names: string[];
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionResponseTypesArrayNestedMessage(t *testing.T) {
	schema := `
message People {
	names Details[]
}

message Details {
	names Text
}

model Person {
	actions {
		read readPerson(name: Text) returns (People) @function
	}
}`
	expected := `
export interface People {
	names: Details[];
}
export interface Details {
	names: string;
}
`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionResponseTypesNestedModels(t *testing.T) {
	schema := `
message PersonResponse {
	sales Sale[]
	person Person
	topSale Sale?
}

model Person {
	actions {
		read readPerson(id) returns (PersonResponse) @function
	}
}

model Sale {

}
	`
	expected := `
export interface PersonResponse {
	sales: Sale[];
	person: Person;
	topSale?: Sale | null;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesNoInputs(t *testing.T) {
	schema := `
model Person {
	actions {
		read getPersonName() returns (Any) @function
	}
}`
	expected := `
export interface GetPersonNameInput {
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteActionInputTypesEmptyInputs(t *testing.T) {
	schema := `
message In {}
model Person {
	actions {
		read getPersonName(In) returns (Any) @function
	}
}`
	expected := `
export interface In {
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteSubscriberMessages(t *testing.T) {
	schema := `
model Member {
	fields {
		name Text
	}
	@on([create, update], verifyEmail)
	@on([create], sendWelcomeEmail)
}`

	expected := `
export type VerifyEmailEvent = (VerifyEmailMemberCreatedEvent | VerifyEmailMemberUpdatedEvent);
export interface VerifyEmailMemberCreatedEvent {
	eventName: "member.created";
	occurredAt: Date;
	identityId?: string;
	target: VerifyEmailMemberCreatedEventTarget;
}
export interface VerifyEmailMemberCreatedEventTarget {
	id: string;
	type: string;
	data: Member;
}
export interface VerifyEmailMemberUpdatedEvent {
	eventName: "member.updated";
	occurredAt: Date;
	identityId?: string;
	target: VerifyEmailMemberUpdatedEventTarget;
}
export interface VerifyEmailMemberUpdatedEventTarget {
	id: string;
	type: string;
	data: Member;
}
export type SendWelcomeEmailEvent = (SendWelcomeEmailMemberCreatedEvent);
export interface SendWelcomeEmailMemberCreatedEvent {
	eventName: "member.created";
	occurredAt: Date;
	identityId?: string;
	target: SendWelcomeEmailMemberCreatedEventTarget;
}
export interface SendWelcomeEmailMemberCreatedEventTarget {
	id: string;
	type: string;
	data: Member;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteSubscriberFunctionWrapperType(t *testing.T) {
	schema := `
model Member {
	fields {
		name Text
	}
	@on([create, update], verifyEmail)
	@on([create], sendWelcomeEmail)
}`

	expected := `
export declare function VerifyEmail(fn: (ctx: SubscriberContextAPI, event: VerifyEmailEvent) => Promise<void>): Promise<void>;
export declare function SendWelcomeEmail(fn: (ctx: SubscriberContextAPI, event: SendWelcomeEmailEvent) => Promise<void>): Promise<void>;`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {

		for _, s := range s.Subscribers {
			writeSubscriberFunctionWrapperType(w, s)
		}
	})
}

func TestWriteFunctionWrapperType(t *testing.T) {
	schema := `
model Person {
	actions {
		get getPerson(id) @function
		create createPerson() @function
		update updatePerson() @function
		delete deletePerson()	@function
		list listPeople()	@function
	}
}
	`
	expected := `
export declare function GetPerson(hooks?: GetPersonHooks) : void
export type GetPersonHooks = {
    
    /**
    * beforeQuery can be used to modify the existing query, or replace it entirely.
    * If the function is marked with the async keyword, then the expected return type is a Promise<Person>.
    * If the function is non-async, then the expected return type is an instance of QueryBuilder.
    */
    beforeQuery?: (ctx: ContextAPI, inputs: GetPersonInput, query: PersonQueryBuilder) => PersonQueryBuilder | Promise<Person>
    
    /**
    * afterQuery is useful for modifying the response data purely for the purposes of presentation, performing custom permission checks, or performing other side effects. 
    */
    afterQuery?: (ctx: ContextAPI, inputs: GetPersonInput, record: Person) => Promise<Person> | Person
}
export declare function CreatePerson(hooks?: CreatePersonHooks) : void
export type CreatePersonHooks = {
    
    /**
    * The beforeWrite hook allows you to modify the values that will be written to the database.
    */
    beforeWrite?: (ctx: ContextAPI, inputs: CreatePersonInput, values: PersonCreateValues) => Promise<PersonCreateValues>
    
    /**
    * The afterWrite hook allows you to perform side effects after the record has been written to the database. Common use cases include creating other models, and performing custom permission checks.
    */
    afterWrite?: (ctx: ContextAPI, inputs: CreatePersonInput, data: Person) => Promise<void>
}
export declare function UpdatePerson(hooks?: UpdatePersonHooks) : void
export type UpdatePersonHooks = {
    
    /**
    * beforeQuery can be used to modify the existing query, or replace it entirely.
    * If the function is marked with the async keyword, then the expected return type is a Promise<Person>.
    * If the function is non-async, then the expected return type is an instance of QueryBuilder.
    */
    beforeQuery?: (ctx: ContextAPI, inputs: UpdatePersonInput, values: UpdatePersonValues) => Promise<Person>
    
    /**
    * afterQuery is useful for modifying the response data purely for the purposes of presentation, performing custom permission checks, or performing other side effects. 
    */
    afterQuery?: (ctx: ContextAPI, inputs: UpdatePersonInput, person: Person) => Promise<Person>
    
    /**
    * The beforeWrite hook allows you to modify the values that will be written to the database.
    */
    beforeWrite?: (ctx: ContextAPI, inputs: UpdatePersonInput, values: UpdatePersonValues) => Promise<UpdatePersonValues>
    
    /**
    * The afterWrite hook allows you to perform side effects after the record has been written to the database. Common use cases include creating other models, and performing custom permission checks.
    */
    afterWrite?: (ctx: ContextAPI, inputs: UpdatePersonInput, data: Person) => Promise<void>
}
export declare function DeletePerson(hooks?: DeletePersonHooks) : void
export type DeletePersonHooks = {
    
    /**
    * beforeQuery can be used to modify the existing query, or replace it entirely.
    * If the function is marked with the async keyword, then the expected return type is a Promise<string>.
    * If the function is non-async, then the expected return type is an instance of QueryBuilder.
    */
    beforeQuery?: (ctx: ContextAPI, inputs: DeletePersonInput, query: PersonQueryBuilder) => PersonQueryBuilder | Promise<string>
    
    /**
    * afterQuery is useful for modifying the response data purely for the purposes of presentation, performing custom permission checks, or performing other side effects. 
    */
    afterQuery?: (ctx: ContextAPI, inputs: DeletePersonInput, deletedId: string) => Promise<string> | string
}
export declare function ListPeople(hooks?: ListPeopleHooks) : void
export type ListPeopleHooks = {
    
    /**
    * beforeQuery can be used to modify the existing query, or replace it entirely.
    * If the function is marked with the async keyword, then the expected return type is a Promise<Person[]>.
    * If the function is non-async, then the expected return type is an instance of QueryBuilder.
    */
    beforeQuery?: (ctx: ContextAPI, inputs: ListPeopleInput, query: PersonQueryBuilder) => PersonQueryBuilder | Promise<Person[]>
    
    /**
    * afterQuery is useful for modifying the response data purely for the purposes of presentation, performing custom permission checks, or performing other side effects. 
    */
    afterQuery?: (ctx: ContextAPI, inputs: ListPeopleInput, records: Person[]) => Promise<Person[]> | Person[]
}
`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		m := proto.FindModel(s.Models, "Person")

		for _, action := range m.Actions {
			writeFunctionWrapperType(w, m, action)
		}
	})
}

func TestWriteFunctionImplementation(t *testing.T) {
	schema := `
model Person {
	actions {
		get getPerson(id) @function
		create createPerson() @function
		update updatePerson() @function
		delete deletePerson()	@function
		list listPeople()	@function
	}
}
	`
	expected := `
const GetPerson = (hooks = {}) => {
	return async function(ctx, inputs) {
		return await runtime.tracing.withSpan('getPerson.DefaultImplementation', async (span) => {
			const models = createModelAPI();
			let wheres = {
				...inputs.where,
			};

			let data;

			// call beforeQuery hook (if defined)
			if (hooks.beforeQuery) {
				let builder = models.person.where(wheres);

				// we don't know if its an instance of PersonQueryBuilder or Promise<Person> so we wrap in Promise.resolve to get the eventual value.
				let resolvedValue;
				await runtime.tracing.withSpan('getPerson.beforeQuery', async (span) => {
					resolvedValue = await hooks.beforeQuery(ctx, deepFreeze(inputs), builder);
				});

				const constructor = resolvedValue?.constructor?.name
				if (constructor === 'QueryBuilder') {
					span.addEvent('using QueryBuilder')
					builder = resolvedValue;
					// in order to populate data, we take the QueryBuilder instance and call the relevant 'terminating' method on it to execute the query
					span.addEvent(builder.sql())
					data = await builder.findOne();
				} else {
					// in this case, the data is just the resolved value of the promise
					span.addEvent('using Model API')
					data = resolvedValue;
				}
			} else {
				// when no beforeQuery hook is defined, use the default implementation
				data = await models.person.findOne(inputs);
			}
			// call afterQuery hook (if defined)
			if (hooks.afterQuery) {
				await runtime.tracing.withSpan('getPerson.afterQuery', async (span) => {
					data = await hooks.afterQuery(ctx, deepFreeze(inputs), data);
				});
			}

			return data;
		});
	};
};
const CreatePerson = (hooks = {}) => {
	return async function(ctx, inputs) {
		return await runtime.tracing.withSpan('createPerson.DefaultImplementation', async (span) => {
			const models = createModelAPI();
			let values = {
				...inputs,
			};

			// call beforeWrite hook (if defined)
			if (hooks.beforeWrite) {
				await runtime.tracing.withSpan('createPerson.beforeWrite', async (span) => {
					values = await hooks.beforeWrite(ctx, deepFreeze(inputs), values);
				});
			}

			// values is the mutated version of inputs.values
			const data = await models.person.create(values);

			// call afterWrite hook (if defined)
			if (hooks.afterWrite) {
				await runtime.tracing.withSpan('createPerson.afterWrite', async (span) => {
					await hooks.afterWrite(ctx, deepFreeze(inputs), data);
				});
			}

			return data;
		});
	};
};
const UpdatePerson = (hooks = {}) => {
	return async function(ctx, inputs) {
		return await runtime.tracing.withSpan('updatePerson.DefaultImplementation', async (span) => {
			const models = createModelAPI();
			let values = Object.assign({}, inputs.values);
			let wheres = Object.assign({}, inputs.where);

			// call beforeWrite hook (if defined)
			if (hooks.beforeWrite) {
				await runtime.tracing.withSpan('updatePerson.beforeWrite', async (span) => {
					values = await hooks.beforeWrite(ctx, deepFreeze(inputs), values);
				});
			}

			let data;
			if (hooks.beforeQuery) {
				await runtime.tracing.withSpan('updatePerson.beforeQuery', async (span) => {
					data = await hooks.beforeQuery(ctx, deepFreeze(inputs), values);
				});
			} else {
				// when no beforeQuery hook is defined, use the default implementation
				data = await models.person.update(wheres, values);
			}

			// call afterQuery hook (if defined)
			if (hooks.afterQuery) {
				await runtime.tracing.withSpan('updatePerson.afterQuery', async (span) => {
					data = await hooks.afterQuery(ctx, deepFreeze(inputs), data);
				});
			}



			// call afterWrite hook (if defined)
			if (hooks.afterWrite) {
				await runtime.tracing.withSpan('updatePerson.afterWrite', async (span) => {
					await hooks.afterWrite(ctx, deepFreeze(inputs), data);
				});
			}

			return data;
		});
	};
};
const DeletePerson = (hooks = {}) => {
	return async function(ctx, inputs) {
		return await runtime.tracing.withSpan('deletePerson.DefaultImplementation', async (span) => {
			const models = createModelAPI();
			let wheres = {
				...inputs.where,
			};

			let data;

			// call beforeQuery hook (if defined)
			if (hooks.beforeQuery) {
				let builder = models.person.where(wheres);

				// we don't know if its an instance of PersonQueryBuilder or Promise<string> so we wrap in Promise.resolve to get the eventual value.
				let resolvedValue;
				await runtime.tracing.withSpan('deletePerson.beforeQuery', async (span) => {
					resolvedValue = await hooks.beforeQuery(ctx, deepFreeze(inputs), builder);
				});

				const constructor = resolvedValue?.constructor?.name
				if (constructor === 'QueryBuilder') {
					span.addEvent('using QueryBuilder')
					builder = resolvedValue;
					// in order to populate data, we take the QueryBuilder instance and call the relevant 'terminating' method on it to execute the query
					span.addEvent(builder.sql())
					data = await builder.delete();
				} else {
					// in this case, the data is just the resolved value of the promise
					span.addEvent('using Model API')
					data = resolvedValue;
				}
			} else {
				// when no beforeQuery hook is defined, use the default implementation
				data = await models.person.delete(inputs);
			}
			// call afterQuery hook (if defined)
			if (hooks.afterQuery) {
				await runtime.tracing.withSpan('deletePerson.afterQuery', async (span) => {
					data = await hooks.afterQuery(ctx, deepFreeze(inputs), data);
				});
			}

			return data;
		});
	};
};
const ListPeople = (hooks = {}) => {
	return async function(ctx, inputs) {
		return await runtime.tracing.withSpan('listPeople.DefaultImplementation', async (span) => {
			const models = createModelAPI();
			let wheres = {
				...inputs.where,
			};

			let data;

			// call beforeQuery hook (if defined)
			if (hooks.beforeQuery) {
				let builder = models.person.where(wheres);

				// we don't know if its an instance of PersonQueryBuilder or Promise<Person[]> so we wrap in Promise.resolve to get the eventual value.
				let resolvedValue;
				await runtime.tracing.withSpan('listPeople.beforeQuery', async (span) => {
					resolvedValue = await hooks.beforeQuery(ctx, deepFreeze(inputs), builder);
				});

				const constructor = resolvedValue?.constructor?.name
				if (constructor === 'QueryBuilder') {
					span.addEvent('using QueryBuilder')
					builder = resolvedValue;
					// in order to populate data, we take the QueryBuilder instance and call the relevant 'terminating' method on it to execute the query
					span.addEvent(builder.sql())
					data = await builder.findMany();
				} else {
					// in this case, the data is just the resolved value of the promise
					span.addEvent('using Model API')
					data = resolvedValue;
				}
			} else {
				// when no beforeQuery hook is defined, use the default implementation
				data = await models.person.findMany(inputs);
			}
			// call afterQuery hook (if defined)
			if (hooks.afterQuery) {
				await runtime.tracing.withSpan('listPeople.afterQuery', async (span) => {
					data = await hooks.afterQuery(ctx, deepFreeze(inputs), data);
				});
			}

			return data;
		});
	};
};
	`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		m := proto.FindModel(s.Models, "Person")

		for _, action := range m.Actions {
			writeFunctionImplementation(w, s, action)
		}
	})
}

func TestWriteJobWrapperType(t *testing.T) {
	schema := `
job JobWithoutInputs {
	@schedule("1 * * * *")
}
job AdHocJobWithInputs {
	inputs {
		nameField Text
		someBool Bool?
	}
	@permission(roles: [Admin])
}
job AdHocJobWithoutInputs {
	@permission(roles: [Admin])
}
role Admin {}
	`
	expected := `
export declare function JobWithoutInputs(fn: (ctx: JobContextAPI) => Promise<void>): Promise<void>;
export declare function AdHocJobWithInputs(fn: (ctx: JobContextAPI, inputs: AdHocJobWithInputsMessage) => Promise<void>): Promise<void>;
export declare function AdHocJobWithoutInputs(fn: (ctx: JobContextAPI) => Promise<void>): Promise<void>;`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		for _, j := range s.Jobs {
			writeJobFunctionWrapperType(w, j)
		}
	})
}

func TestWriteJobInputs(t *testing.T) {
	schema := `
job JobWithoutInputs {
	@schedule("1 * * * *")
}
job AdHocJobWithInputs {
	inputs {
		nameField Text
		someBool Bool?
	}
	@permission(roles: [Admin])
}
job AdHocJobWithoutInputs {
	@permission(roles: [Admin])
}
role Admin {}`

	expected := `
export interface AdHocJobWithInputsMessage {
	nameField: string;
	someBool?: any;
}`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeMessages(w, s, false)
	})
}

func TestWriteTestingTypes(t *testing.T) {
	schema := `
model Person {
	actions {
		get getPerson(id)
		create createPerson()
		update updatePerson() {
			@function
		}
		delete deletePerson() {
			@function
		}
		list listPeople() {
			@function
		}
	}
}`

	expected := `
import * as sdk from "@teamkeel/sdk";
import * as runtime from "@teamkeel/functions-runtime";
import "@teamkeel/testing-runtime";

export interface GetPersonInput {
	id: string;
}
export interface CreatePersonInput {
}
export interface UpdatePersonWhere {
}
export interface UpdatePersonValues {
}
export interface UpdatePersonInput {
	where?: UpdatePersonWhere;
	values?: UpdatePersonValues;
}
export interface DeletePersonInput {
}
export interface ListPeopleWhere {
}
export interface ListPeopleInput {
	where?: ListPeopleWhere;
	first?: number;
	after?: string;
	last?: number;
	before?: string;
}
export interface EmailPasswordInput {
	email: string;
	password: string;
}
export interface AuthenticateInput {
	createIfNotExists?: boolean;
	emailPassword: EmailPasswordInput;
}
export interface AuthenticateResponse {
	identityCreated: boolean;
	token: string;
}
export interface RequestPasswordResetInput {
	email: string;
	redirectUrl: string;
}
export interface RequestPasswordResetResponse {
}
export interface ResetPasswordInput {
	token: string;
	password: string;
}
export interface ResetPasswordResponse {
}
declare class ActionExecutor {
	withIdentity(identity: sdk.Identity): ActionExecutor;
	withAuthToken(token: string): ActionExecutor;
	getPerson(i: GetPersonInput): Promise<sdk.Person | null>;
	createPerson(i?: CreatePersonInput): Promise<sdk.Person>;
	updatePerson(i?: UpdatePersonInput): Promise<sdk.Person>;
	deletePerson(i?: DeletePersonInput): Promise<string>;
	listPeople(i?: ListPeopleInput): Promise<{results: sdk.Person[], pageInfo: runtime.PageInfo}>;
	authenticate(i: AuthenticateInput): Promise<AuthenticateResponse>;
	requestPasswordReset(i: RequestPasswordResetInput): Promise<RequestPasswordResetResponse>;
	resetPassword(i: ResetPasswordInput): Promise<ResetPasswordResponse>;
}
export declare const actions: ActionExecutor;
export declare const models: sdk.ModelsAPI;
export declare function resetDatabase(): Promise<void>;`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeTestingTypes(w, s)
	})
}

func TestWriteTestingTypesJobs(t *testing.T) {
	schema := `
job JobWithoutInputs {
	@schedule("1 * * * *")
}
job AdHocJobWithInputs {
	inputs {
		nameField Text
		someBool Bool?
	}
	@permission(roles: [Admin])
}
job AdHocJobWithoutInputs {
	@permission(roles: [Admin])
}
role Admin {}`

	expected := `
import * as sdk from "@teamkeel/sdk";
import * as runtime from "@teamkeel/functions-runtime";
import "@teamkeel/testing-runtime";

export interface AdHocJobWithInputsMessage {
	nameField: string;
	someBool?: any;
}
export interface EmailPasswordInput {
	email: string;
	password: string;
}
export interface AuthenticateInput {
	createIfNotExists?: boolean;
	emailPassword: EmailPasswordInput;
}
export interface AuthenticateResponse {
	identityCreated: boolean;
	token: string;
}
export interface RequestPasswordResetInput {
	email: string;
	redirectUrl: string;
}
export interface RequestPasswordResetResponse {
}
export interface ResetPasswordInput {
	token: string;
	password: string;
}
export interface ResetPasswordResponse {
}
declare class ActionExecutor {
	withIdentity(identity: sdk.Identity): ActionExecutor;
	withAuthToken(token: string): ActionExecutor;
	authenticate(i: AuthenticateInput): Promise<AuthenticateResponse>;
	requestPasswordReset(i: RequestPasswordResetInput): Promise<RequestPasswordResetResponse>;
	resetPassword(i: ResetPasswordInput): Promise<ResetPasswordResponse>;
}
type JobOptions = { scheduled?: boolean } | null
declare class JobExecutor {
	withIdentity(identity: sdk.Identity): JobExecutor;
	withAuthToken(token: string): JobExecutor;
	jobWithoutInputs(o?: JobOptions): Promise<void>;
	adHocJobWithInputs(i: AdHocJobWithInputsMessage, o?: JobOptions): Promise<void>;
    adHocJobWithoutInputs(o?: JobOptions): Promise<void>;
}
export declare const jobs: JobExecutor;
export declare const actions: ActionExecutor;
export declare const models: sdk.ModelsAPI;
export declare function resetDatabase(): Promise<void>;`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeTestingTypes(w, s)
	})
}

func TestWriteTestingTypesSubscribers(t *testing.T) {
	schema := `
model ClubHouse {
	@on([create, update], verifyEmail)
}`

	expected := `
export type VerifyEmailEvent = (VerifyEmailClubHouseCreatedEvent | VerifyEmailClubHouseUpdatedEvent);
export interface VerifyEmailClubHouseCreatedEvent {
	eventName: "club_house.created";
	occurredAt: Date;
	identityId?: string;
	target: VerifyEmailClubHouseCreatedEventTarget;
}
export interface VerifyEmailClubHouseCreatedEventTarget {
	id: string;
	type: string;
	data: sdk.ClubHouse;
}
export interface VerifyEmailClubHouseUpdatedEvent {
	eventName: "club_house.updated";
	occurredAt: Date;
	identityId?: string;
	target: VerifyEmailClubHouseUpdatedEventTarget;
}
export interface VerifyEmailClubHouseUpdatedEventTarget {
	id: string;
	type: string;
	data: sdk.ClubHouse;
}
declare class ActionExecutor {
	withIdentity(identity: sdk.Identity): ActionExecutor;
	withAuthToken(token: string): ActionExecutor;
	authenticate(i: AuthenticateInput): Promise<AuthenticateResponse>;
	requestPasswordReset(i: RequestPasswordResetInput): Promise<RequestPasswordResetResponse>;
	resetPassword(i: ResetPasswordInput): Promise<ResetPasswordResponse>;
}
declare class SubscriberExecutor {
	verifyEmail(e: VerifyEmailEvent): Promise<void>;
}
export declare const subscribers: SubscriberExecutor;
export declare const actions: ActionExecutor;
export declare const models: sdk.ModelsAPI;
export declare function resetDatabase(): Promise<void>;`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeTestingTypes(w, s)
	})
}

func TestWriteTableConfig(t *testing.T) {
	schema := `
model Publisher {
	fields {
		authors Author[]
	}
}
model Author {
	fields {
		publisher Publisher
		books Book[]
	}
}
model Book {
	fields {
		author Author
	}
}`
	expected := `
const tableConfigMap = {
	"author": {
		"books": {
			"foreignKey": "author_id",
			"referencesTable": "book",
			"relationshipType": "hasMany"
		},
		"publisher": {
			"foreignKey": "publisher_id",
			"referencesTable": "publisher",
			"relationshipType": "belongsTo"
		}
	},
	"book": {
		"author": {
			"foreignKey": "author_id",
			"referencesTable": "author",
			"relationshipType": "belongsTo"
		}
	},
	"publisher": {
		"authors": {
			"foreignKey": "publisher_id",
			"referencesTable": "author",
			"relationshipType": "hasMany"
		}
	}
};`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeTableConfig(w, s.Models)
	})
}

func TestWriteTestingTypesEnums(t *testing.T) {
	schema := `
enum Hobby {
	Tennis
	Chess
}
model Person {
	fields {
		hobby Hobby
	}
	actions {
		list peopleByHobby(hobby)
	}
}
	`
	expected := `
import * as sdk from "@teamkeel/sdk";
import * as runtime from "@teamkeel/functions-runtime";
import "@teamkeel/testing-runtime";

export interface HobbyQueryInput {
	equals?: Hobby | null;
	notEquals?: Hobby | null;
	oneOf?: Hobby[];
}
export interface PeopleByHobbyWhere {
	hobby: HobbyQueryInput;
}
export interface PeopleByHobbyInput {
	where: PeopleByHobbyWhere;
	first?: number;
	after?: string;
	last?: number;
	before?: string;
}
export interface EmailPasswordInput {
	email: string;
	password: string;
}
export interface AuthenticateInput {
	createIfNotExists?: boolean;
	emailPassword: EmailPasswordInput;
}
export interface AuthenticateResponse {
	identityCreated: boolean;
	token: string;
}
export interface RequestPasswordResetInput {
	email: string;
	redirectUrl: string;
}
export interface RequestPasswordResetResponse {
}
export interface ResetPasswordInput {
	token: string;
	password: string;
}
export interface ResetPasswordResponse {
}
declare class ActionExecutor {
	withIdentity(identity: sdk.Identity): ActionExecutor;
	withAuthToken(token: string): ActionExecutor;
	peopleByHobby(i: PeopleByHobbyInput): Promise<{results: sdk.Person[], pageInfo: runtime.PageInfo}>;
	authenticate(i: AuthenticateInput): Promise<AuthenticateResponse>;
	requestPasswordReset(i: RequestPasswordResetInput): Promise<RequestPasswordResetResponse>;
	resetPassword(i: ResetPasswordInput): Promise<ResetPasswordResponse>;
}
export declare const actions: ActionExecutor;
export declare const models: sdk.ModelsAPI;
export declare function resetDatabase(): Promise<void>;`

	runWriterTest(t, schema, expected, func(s *proto.Schema, w *codegen.Writer) {
		writeTestingTypes(w, s)
	})
}

func TestTestingActionExecutor(t *testing.T) {
	tmpDir := t.TempDir()

	wd, err := os.Getwd()
	require.NoError(t, err)

	err = Bootstrap(tmpDir, WithPackagesPath(filepath.Join(wd, "../packages")))
	require.NoError(t, err)

	_, err = testhelpers.NpmInstall(tmpDir)
	require.NoError(t, err)

	err = codegen.GeneratedFiles{
		{
			Contents: `
			model Person {
				actions {
					get getPerson(id) @function
				}
			}
			`,
			Path: "schema.keel",
		},
		{
			Contents: `
			import { actions } from "@teamkeel/testing";
			import { test, expect } from "vitest";

			test("action execution", async () => {
				const res = await actions.getPerson({id: "1234"});
				expect(res).toEqual({
					name: "Barney",
				});
			});

			test("toHaveAuthorizationError custom matcher", async () => {
				const p = Promise.reject({code: "ERR_PERMISSION_DENIED"});
				await expect(p).toHaveAuthorizationError();
			});
			`,
			Path: "code.test.ts",
		},
	}.Write(tmpDir)
	require.NoError(t, err)

	builder := schema.Builder{}
	schema, err := builder.MakeFromDirectory(tmpDir)
	require.NoError(t, err)

	files, err := Generate(context.Background(), schema)
	require.NoError(t, err)

	err = files.Write(tmpDir)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		assert.True(t, strings.HasSuffix(r.URL.Path, "/getPerson"))

		b, err := io.ReadAll(r.Body)
		assert.NoError(t, err)

		type Payload struct {
			ID string
		}
		var payload Payload
		err = json.Unmarshal(b, &payload)
		assert.NoError(t, err)
		assert.Equal(t, "1234", payload.ID)

		_, err = w.Write([]byte(`{"name": "Barney"}`))
		require.NoError(t, err)
	}))
	defer server.Close()

	cmd := exec.Command("npx", "tsc", "--noEmit")
	cmd.Dir = tmpDir
	b, err := cmd.CombinedOutput()
	if !assert.NoError(t, err) {
		fmt.Println(string(b))
		t.FailNow()
	}

	cmd = exec.Command("npx", "vitest", "run", "--config", ".build/vitest.config.mjs")
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(), []string{
		"KEEL_DB_CONN_TYPE=pg",
		"KEEL_DB_CONN=postgresql://postgres:postgres@localhost:8001/keel",
		fmt.Sprintf("KEEL_TESTING_ACTIONS_API_URL=%s", server.URL),
	}...)

	b, err = cmd.CombinedOutput()
	if !assert.NoError(t, err) {
		fmt.Println(string(b))
	}
}

func TestSDKTypings(t *testing.T) {
	tmpDir := t.TempDir()

	wd, err := os.Getwd()
	require.NoError(t, err)

	err = Bootstrap(tmpDir, WithPackagesPath(filepath.Join(wd, "../packages")))
	require.NoError(t, err)

	_, err = testhelpers.NpmInstall(tmpDir)
	require.NoError(t, err)

	err = codegen.GeneratedFiles{
		{
			Path: "schema.keel",
			Contents: `
				model Person {
					fields {
						name Text
						lastName Text?
					}
					actions {
						get getPerson(id: Number) @function
					}
				}`,
		},
	}.Write(tmpDir)
	require.NoError(t, err)

	type fixture struct {
		name  string
		code  string
		error string
	}

	fixtures := []fixture{
		{
			name: "findOne",
			code: `
				import { models, GetPerson } from "@teamkeel/sdk";
		
				export default GetPerson({
					beforeQuery: async (ctx, inputs, query) => {
						const p = await models.person.findOne({
							id: 123
						});

						return p;
					}
				});
			`,
			error: "Type 'number' is not assignable to type 'string'",
		},
		{
			name: "findOne - can return null",
			code: `
				import { models, GetPerson } from "@teamkeel/sdk";
		
				export default GetPerson({
					beforeQuery: async (ctx, inputs, query) => {
						const r = await models.person.findOne({
							id: "1234",
						});
						// the console.log of r.id triggers the typeerror
						console.log(r.id);
						return r;
					}
				});
			`,
			error: "'r' is possibly 'null'",
		},
		{
			name: "testing actions executor - input types",
			code: `
				import { actions } from "@teamkeel/testing";
		
				async function foo() {
					await actions.getPerson({
						id: "1234",
					});
				}
			`,
			error: "code.ts(6,7): error TS2322: Type 'string' is not assignable to type 'number'",
		},
		{
			name: "testing actions executor - return types",
			code: `
				import { actions } from "@teamkeel/testing";
		
				async function foo() {
					const p = await actions.getPerson({
						id: 1234,
					});
					console.log(p.id);
				}
			`,
			error: "code.ts(8,18): error TS18047: 'p' is possibly 'null'",
		},
		{
			name: "testing actions executor - withIdentity",
			code: `
				import { actions } from "@teamkeel/testing";
		
				async function foo() {
					await actions.withIdentity(null).getPerson({
						id: 1234,
					});
				}
			`,
			error: "code.ts(5,33): error TS2345: Argument of type 'null' is not assignable to parameter of type 'Identity'",
		},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			err := codegen.GeneratedFiles{
				{
					Path:     "code.ts",
					Contents: fixture.code,
				},
			}.Write(tmpDir)
			require.NoError(t, err)

			builder := schema.Builder{}
			schema, err := builder.MakeFromDirectory(tmpDir)
			require.NoError(t, err)

			files, err := Generate(context.Background(), schema)
			require.NoError(t, err)

			err = files.Write(tmpDir)
			require.NoError(t, err)

			c := exec.Command("npx", "tsc", "--noEmit")
			c.Dir = tmpDir
			b, _ := c.CombinedOutput()
			assert.Contains(t, string(b), fixture.error)
		})
	}
}

func normalise(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\t", "    ")
}

func runWriterTest(t *testing.T, schemaString string, expected string, fn func(s *proto.Schema, w *codegen.Writer)) {
	b := schema.Builder{}
	s, err := b.MakeFromString(schemaString)
	require.NoError(t, err)
	w := &codegen.Writer{}
	fn(s, w)
	diff := diffmatchpatch.New()
	diffs := diff.DiffMain(normalise(expected), normalise(w.String()), true)
	if !strings.Contains(normalise(w.String()), normalise(expected)) {
		t.Errorf("generated code does not match expected:\n%s", diffPrettyText(diffs))

		t.Errorf("\nExpected:\n---------\n%s", normalise(expected))
		t.Errorf("\nActual:\n---------\n%s", normalise(w.String()))
	}
}

// diffPrettyText is a port of the same function from the diffmatchpatch
// lib but with better handling of whitespace diffs (by using background colours)
func diffPrettyText(diffs []diffmatchpatch.Diff) string {
	var buff strings.Builder

	for _, diff := range diffs {
		switch diff.Type {
		case diffmatchpatch.DiffInsert:
			if strings.TrimSpace(diff.Text) == "" {
				buff.WriteString(colors.Green(fmt.Sprint(diff.Text)).String())
			} else {
				buff.WriteString(colors.Green(fmt.Sprint(diff.Text)).Highlight().String())
			}
		case diffmatchpatch.DiffDelete:
			if strings.TrimSpace(diff.Text) == "" {
				buff.WriteString(colors.Red(diff.Text).String())
			} else {
				buff.WriteString(colors.Red(fmt.Sprint(diff.Text)).Highlight().String())
			}
		case diffmatchpatch.DiffEqual:
			buff.WriteString(diff.Text)
		}
	}

	return buff.String()
}
