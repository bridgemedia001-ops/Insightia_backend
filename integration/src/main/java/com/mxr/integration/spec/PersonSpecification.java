package com.mxr.integration.spec;

import org.springframework.data.jpa.domain.Specification;

import com.mxr.integration.model.Person;

public class PersonSpecification {

    public static Specification<Person> hasGender(String gender) {
        return (root, query, cb) -> gender == null ? null
                : cb.equal(cb.lower(root.get("gender")), gender.toLowerCase());
    }

    public static Specification<Person> hasCountryId(String countryId) {
        return (root, query, cb) -> countryId == null ? null
                : cb.equal(cb.lower(root.get("countryId")), countryId.toLowerCase());
    }

    public static Specification<Person> hasAgeGroup(String ageGroup) {
        return (root, query, cb) -> ageGroup == null ? null
                : cb.equal(cb.lower(root.get("ageGroup")), ageGroup.toLowerCase());
    }

    // public static Specification<Person> hasName(String name) {
    // return (root, query, cb) -> name == null ? null :
    // cb.equal(cb.lower(root.get("name")), name.toLowerCase());
    // }

    public static Specification<Person> greaterThanAge(Integer minimumAge) {
        return (root, query, cb) -> minimumAge == null ? cb.conjunction()
                : cb.greaterThanOrEqualTo(root.get("age"), minimumAge);
    }

    public static Specification<Person> lessThanAge(Integer maximumAge) {
        return (root, query, cb) -> maximumAge == null ? cb.conjunction()
                : cb.lessThanOrEqualTo(root.get("age"), maximumAge);
    }

    public static Specification<Person> greaterThanGenderProbability(Double genderProbability) {
        return (root, query, cb) -> genderProbability == null ? cb.conjunction()
                : cb.greaterThanOrEqualTo(root.get("genderProbability"), genderProbability);
    }

    public static Specification<Person> greaterThanCountryProbability(Double countryProbability) {
        return (root, query, cb) -> countryProbability == null ? cb.conjunction()
                : cb.greaterThanOrEqualTo(root.get("countryProbability"), countryProbability);
    }
}
