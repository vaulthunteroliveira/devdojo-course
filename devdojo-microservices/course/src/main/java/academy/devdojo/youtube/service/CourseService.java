package academy.devdojo.youtube.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import academy.devdojo.youtube.model.Course;
import academy.devdojo.youtube.repository.CourseRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class CourseService {

	private final CourseRepository courseRepository;
	
	public Iterable<Course> list(Pageable pageaable){
		log.info("listing all courses");
		return courseRepository.findAll(pageaable);
	}
}
